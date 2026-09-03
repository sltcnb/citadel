"""Elasticsearch service — index management and querying.

The authoritative index template for fo-case-* indices lives at
``elasticsearch/index_templates/fo-cases-template.json`` (applied to the
cluster out-of-band, verified live). Keep field references here in sync with
that file — e.g. ``evtx.channel`` and ``http.method`` are plain keywords with
NO ``.keyword`` sub-field.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from typing import Any

from config import settings

logger = logging.getLogger(__name__)

ES_URL = settings.ELASTICSEARCH_URL


def _install_es_auth() -> None:
    """ES runs with security enabled, so every request needs HTTP Basic auth.
    Rather than thread credentials through every urllib call site, install a
    process-wide opener whose auth handler is SCOPED to the ES host — MinIO/S3
    and any other urllib traffic never receive the credentials. Reactive (adds
    auth on the 401 challenge), which the native-realm ES sends. No-op when
    credentials are not configured."""
    user = settings.ELASTICSEARCH_USERNAME
    password = settings.ELASTICSEARCH_PASSWORD
    if not (user and password):
        logger.warning("No Elasticsearch credentials configured; requests will be unauthenticated")
        return
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, ES_URL, user, password)
    urllib.request.install_opener(
        urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(mgr))
    )


_install_es_auth()


class SearchError(RuntimeError):
    """Elasticsearch REJECTED a search/facet query (HTTP 400).

    Distinct from "no data": a missing index (404 / index_not_found) is a
    legitimate empty result, but a 400 means the query itself is broken —
    reporting it as "0 results" is how bad queries stay indistinguishable
    from queries that genuinely matched nothing. Routers translate this into
    an HTTP 400 (same pattern as rule_eval.RuleEvalError).
    """


def _es_error_reason(exc: urllib.error.HTTPError) -> str:
    """Extract Elasticsearch's own reason string from an HTTPError body."""
    try:
        err = json.loads(exc.read() or b"{}")
        error = err.get("error", {})
        root = error.get("root_cause") or []
        return (root[0].get("reason") if root else None) or error.get("reason") or str(exc)
    except Exception:
        return str(exc)


def _is_missing_index(exc: urllib.error.HTTPError, reason: str = "") -> bool:
    """True when the failure just means the case has no such index (legit empty)."""
    return (
        exc.code == 404
        or "index_not_found" in reason
        or "no such index" in reason
        or "index_not_found" in str(exc)
    )


# DNS query-name fields actually emitted by the parsers (verified against
# tools/babel): pcap → dns.query_name, Suricata → suricata.dns.rrname,
# Zeek dns.log → zeek.query. ECS's ``dns.question.name`` only appears in the
# rosetta fieldmap for an artifact_type no parser produces, so querying it
# alone always matches nothing. All three are dynamically mapped text+keyword.
DNS_NAME_FIELDS = ["dns.query_name", "suricata.dns.rrname", "zeek.query"]
DNS_NAME_KEYWORD_FIELDS = [f"{f}.keyword" for f in DNS_NAME_FIELDS]


def es_request(method: str, path: str, body: dict | None = None) -> dict:
    url = f"{ES_URL}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


# Backward-compat alias. Many routers do `from services.elasticsearch import
# _request as es_req` — keep the private name pointing at the public one so
# those imports keep working untouched.
_request = es_request


# A balanced `/regex/` token (slash, body, slash). Used to decide whether a
# query is *intentionally* a Lucene regex before we touch its slashes.
_BALANCED_REGEX_RE = re.compile(r"/(?:[^/\\]|\\.)+/")


# Cost bounds for user-supplied Lucene. `query_string` with fields: ["*"]
# accepts inline /regex/ and leading wildcards on purpose — that is the search
# feature — so the defence is to bound what a query may COST rather than to
# escape the syntax away (escaping every metacharacter would remove
# field:value, AND/OR and wildcard search entirely).
#
# MAX_DETERMINIZED_STATES caps the automaton Lucene will build for a regex or
# wildcard: past it Elasticsearch answers with a "too complex" error instead
# of burning CPU. ES's own default is 10 000; we pass it explicitly so the
# bound is visible and cannot drift with a version bump.
_MAX_QUERY_LEN = 4096
_MAX_DETERMINIZED_STATES = 10000
# Server-side wall clock per shard. A query that cannot finish in this budget
# returns partial results rather than pinning a data node.
_SEARCH_TIMEOUT = "30s"


def validate_lucene_query(query: str) -> str | None:
    """Cheap structural pre-check for a Lucene ``query_string`` expression.

    Catches the syntax mistakes that make Elasticsearch return a bare HTTP 400
    *before* we spend a round-trip — and lets the caller hand back a clear,
    actionable message instead of "Bad Request". Returns an error string on a
    problem, or ``None`` when the query looks structurally sound. This is a
    structural check only (balance + dangling operators); it does NOT validate
    field names or semantics, and it deliberately ignores escaped/quoted spans.

    Empty / whitespace-only queries are valid (they mean match-all upstream).
    """
    if not query or not query.strip():
        return None

    if len(query) > _MAX_QUERY_LEN:
        return (
            f"Query is too long ({len(query)} characters; limit "
            f"{_MAX_QUERY_LEN}). Narrow it or use filters instead."
        )

    # Walk the string, tracking quote and escape state so brackets/parens inside
    # a quoted phrase or escaped with a backslash don't count toward balance.
    paren = 0
    square = 0
    in_quote = False
    escaped = False
    for ch in query:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            in_quote = not in_quote
            continue
        if in_quote:
            continue
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
            if paren < 0:
                return "unbalanced parentheses — a ')' has no matching '('."
        elif ch == "[":
            square += 1
        elif ch == "]":
            square -= 1
            if square < 0:
                return "unbalanced range brackets — a ']' has no matching '['."
    if in_quote:
        return 'unterminated quote — a \'"\' is never closed.'
    if paren > 0:
        return "unbalanced parentheses — a '(' is never closed."
    if square > 0:
        return "unbalanced range brackets — a '[' is never closed (use [START TO END])."

    # Dangling boolean operator: `… AND`, `foo OR`, `NOT` alone, or a leading
    # `AND foo`. These all 400 in query_string.
    stripped = query.strip()
    if re.search(r"(?:^|\s)(AND|OR|NOT|&&|\|\|)\s*$", stripped):
        return "query ends with a dangling boolean operator (AND/OR/NOT) — remove it or add the missing clause."
    if re.match(r"^(AND|OR|&&|\|\|)\b", stripped):
        return "query starts with a boolean operator — remove the leading AND/OR."

    return None


def escape_lucene_query(query: str, preserve_regex: bool = False) -> str:
    """Neutralise stray forward slashes in a Lucene ``query_string``.

    Lucene treats an unescaped ``/`` as the start of a regexp; a lone or
    unbalanced slash (e.g. ``message:*HTTP/2*`` or a URL path) makes the whole
    query unparseable and Elasticsearch returns **HTTP 400**. Models can't be
    relied on to escape these consistently, so we do it server-side: every
    ``/`` that isn't already backslash-escaped becomes ``\\/`` (a literal slash
    to Lucene).

    With ``preserve_regex=True`` a query that contains a balanced ``/regex/``
    token is left untouched, so the UI's deliberate regex search still works.

    NOTE: this is a parse-error guard, NOT a sanitiser. Lucene syntax
    (``field:value``, ``AND``/``OR``, wildcards, ranges, inline regex) reaches
    Elasticsearch intentionally — that is the search feature. Escaping every
    metacharacter here would remove it. Query *cost* is bounded separately by
    ``_MAX_QUERY_LEN`` and ``max_determinized_states`` on each query_string.
    """
    if not query:
        return query
    if preserve_regex and _BALANCED_REGEX_RE.search(query):
        return query
    return re.sub(r"(?<!\\)/", r"\\/", query)


# --- Reusable query-building helpers (pure functions, unit-testable) ---


def build_bool_query(
    must: list[dict] | None = None,
    filter: list[dict] | None = None,
    must_not: list[dict] | None = None,
    should: list[dict] | None = None,
) -> dict:
    """Return a ``{"bool": {...}}`` dict, omitting empty clauses."""
    bool_body: dict[str, Any] = {}
    if must:
        bool_body["must"] = must
    if filter:
        bool_body["filter"] = filter
    if must_not:
        bool_body["must_not"] = must_not
    if should:
        bool_body["should"] = should
    return {"bool": bool_body}


# Elasticsearch's default max_result_window — shallow `from` paging cannot go
# past this; callers must switch to search_after cursor pagination.
MAX_RESULT_WINDOW = 10000


def paginate(page: int, size: int, max_window: int = MAX_RESULT_WINDOW) -> dict:
    """Return ``{"from": ..., "size": ...}`` clamped so ``from + size`` never
    exceeds ``max_window``. ``from`` is clamped to ``max(0, max_window - size)``."""
    frm = page * size
    frm = min(frm, max(0, max_window - size))
    frm = max(0, frm)
    return {"from": frm, "size": size}


def total_hits_setting(threshold: int | None = None) -> dict:
    """Return a ``track_total_hits`` setting for use where exact counts matter.

    With no threshold → exact count (``True``); with an int → cap the count at
    that value (cheaper for huge unfiltered result sets)."""
    return {"track_total_hits": threshold if threshold is not None else True}


def list_case_indices(case_id: str) -> list[str]:
    """Return all Elasticsearch indices for a given case."""
    try:
        result = _request("GET", f"/_cat/indices/fo-case-{case_id}-*?format=json")
        return [idx["index"] for idx in result]
    except Exception:
        return []


def list_artifact_types(case_id: str) -> list[str]:
    """Return distinct artifact types present in the case."""
    indices = list_case_indices(case_id)
    prefix = f"fo-case-{case_id}-"
    return [idx[len(prefix) :] for idx in indices if idx.startswith(prefix)]


def count_case_events(case_id: str) -> int:
    """Return total event count across all case indices."""
    try:
        result = _request("GET", f"/fo-case-{case_id}-*/_count")
        return result.get("count", 0)
    except Exception:
        return 0


def bulk_case_stats(case_ids: list[str]) -> dict[str, dict]:
    """
    Return event_count and artifact_types for multiple cases in a single
    _cat/indices call. Used by the case list endpoint to avoid per-case queries.
    """
    if not case_ids:
        return {}

    id_set = set(case_ids)
    result: dict[str, dict] = {cid: {"event_count": 0, "artifact_types": []} for cid in case_ids}

    # One _cat/indices call for event counts and artifact types across all cases
    try:
        indices = _request("GET", "/_cat/indices/fo-case-*?format=json&h=index,docs.count")
        for entry in indices:
            name = entry.get("index", "")
            # index format: fo-case-{case_id}-{artifact_type}
            if not name.startswith("fo-case-"):
                continue
            rest = name[len("fo-case-") :]
            dash = rest.find("-")
            if dash == -1:
                continue
            cid, atype = rest[:dash], rest[dash + 1 :]
            if cid in id_set:
                result[cid]["artifact_types"].append(atype)
                try:
                    result[cid]["event_count"] += int(entry.get("docs.count") or 0)
                except (TypeError, ValueError):
                    pass
    except Exception:
        pass

    return result


_SEARCH_FIELDS = [
    "message",
    "host.hostname",
    "user.name",
    "process.name",
    "process.command_line",
    "process.args",
    "network.src_ip",
    "network.dst_ip",
    "network.protocol",
    "network.action",
    "http.request_path",
    "http.user_agent",
]


# Detect Lucene operators / structure; if any present, treat the input as a
# crafted query and don't apply the smart-wildcard fallback.
_LUCENE_OPERATORS_RE = __import__("re").compile(
    r"""(?:                       # any of:
        :|                        # field qualifier
        \bAND\b|\bOR\b|\bNOT\b|   # boolean ops
        [()\[\]{}"\\]|            # grouping / quoting / escape
        /[^/]+/|                  # /regex/
        [*?]|                     # wildcards
        \^[0-9]                   # boost
    )""",
    __import__("re").VERBOSE,
)


def _looks_like_bare_ioc(q: str) -> bool:
    """True if q has no Lucene operators — treat as a bare IOC-style token."""
    q = (q or "").strip()
    if not q:
        return False
    if _LUCENE_OPERATORS_RE.search(q):
        return False
    # Don't double-wildcard a short word; only meaningful for IOC-like strings
    # containing punctuation (dots/dashes/slashes/colons).
    return any(c in q for c in ".-/_")


_ARTIFACT_TYPE_RE = re.compile(r"[a-z0-9_]+")


def build_index_expression(case_id: str, artifact_type: str | None) -> str:
    """ES index expression for event reads, confined to ``case_id``.

    ``artifact_type`` may be a comma-separated list (same convention as
    rule_eval.index_for). Every part is validated and re-anchored with the
    case prefix: ES treats a comma in the request path as a multi-index list,
    so interpolating the raw value would let a caller search ANY case's
    indices (``artifact_type="x,fo-case-<victim>-*"``) — a cross-tenant read.
    """
    if not artifact_type:
        return f"fo-case-{case_id}-*"
    parts = [p.strip() for p in str(artifact_type).split(",") if p.strip()]
    if parts == ["*"]:
        return f"fo-case-{case_id}-*"
    if not parts or any(_ARTIFACT_TYPE_RE.fullmatch(p) is None for p in parts):
        raise ValueError(
            f"Invalid artifact_type {artifact_type!r}: expected comma-separated "
            "artifact types (lowercase letters, digits, underscores)"
        )
    return ",".join(f"fo-case-{case_id}-{p}" for p in parts)


def search_events(
    case_id: str,
    query: str = "",
    artifact_type: str | None = None,
    from_ts: str | None = None,
    to_ts: str | None = None,
    extra_filters: list[dict] | None = None,
    page: int = 0,
    size: int = 100,
    sort_field: str = "timestamp",
    sort_order: str = "asc",
    regexp: bool = False,  # kept for API compat, ignored — use /regex/ in query instead
    search_after: list | None = None,
) -> dict[str, Any]:
    """
    Search events in a case with full-text query and field filters.
    Returns ES hits response dict.
    """
    index = build_index_expression(case_id, artifact_type)

    must_clauses: list[dict] = []
    filter_clauses: list[dict] = []

    if query:
        # Stray forward slashes (URL paths, "HTTP/2") otherwise make Lucene
        # try to parse a regexp and 400 the whole query. Escape them — but keep
        # a deliberate /regex/ search intact.
        query = escape_lucene_query(query, preserve_regex=True)
        # Full Lucene query_string over all indexed fields.
        # Inline regexes work natively: /pattern/ syntax in the query string.
        #
        # Smart-bare-term: if the input is a single token with NO Lucene operators
        # (e.g. "pan.bar", "192.168.1.1", "evil.exe"), augment the search with
        # a wildcard variant so substring/IOC-style searches match across
        # tokenized URL/path fields where analyzer splits on punctuation.
        clauses = [
            {
                "query_string": {
                    "query": query,
                    "default_operator": "AND",
                    "fields": ["*"],
                    "allow_leading_wildcard": True,
                    "analyze_wildcard": True,
                    "max_determinized_states": _MAX_DETERMINIZED_STATES,
                }
            }
        ]
        if _looks_like_bare_ioc(query):
            wq = f"*{query.strip()}*"
            clauses.append(
                {
                    "query_string": {
                        "query": wq,
                        "fields": ["*"],
                        "allow_leading_wildcard": True,
                        "analyze_wildcard": True,
                        "max_determinized_states": _MAX_DETERMINIZED_STATES,
                    }
                }
            )
        if len(clauses) == 1:
            must_clauses.extend(clauses)
        else:
            must_clauses.append({"bool": {"should": clauses, "minimum_should_match": 1}})

    if from_ts or to_ts:
        range_filter: dict = {"range": {"timestamp": {}}}
        if from_ts:
            range_filter["range"]["timestamp"]["gte"] = from_ts
        if to_ts:
            range_filter["range"]["timestamp"]["lte"] = to_ts
        filter_clauses.append(range_filter)

    if extra_filters:
        filter_clauses.extend(extra_filters)

    es_query: dict[str, Any] = build_bool_query(
        must=must_clauses or [{"match_all": {}}],
        filter=filter_clauses,
    )

    if sort_field == "_severity":
        # Unified severity sort across artifact types — hayabusa.level_int
        # (long), finding severity_int, or text levels normalized to 1-5.
        # Sorting on a single field can't work: no field exists on every doc
        # (evtx.level is plain keyword, hayabusa nests under hayabusa.*).
        sort_clause: list = [
            {"_script": {"type": "number", "order": sort_order, "script": {"source": _SEVERITY_SORT_SCRIPT}}},
            {"_doc": {"order": "asc"}},
        ]
    else:
        sort_clause = [
            {sort_field: {"order": sort_order, "unmapped_type": "keyword", "missing": "_last"}},
            {"_doc": {"order": "asc"}},
        ]

    body = {
        "query": es_query,
        "size": size,
        "sort": sort_clause,
        "_source": {"excludes": ["raw.xml"]},
        # Always report the EXACT total — no 10k (or 100k) cap. For match_all this
        # is cheap (Lucene knows the segment doc counts); for filtered queries the
        # analyst gets the true "N results" instead of a "10000+" stub.
        **total_hits_setting(None),
    }
    # search_after = cursor pagination (deep, O(1)) — required past the 10k
    # max_result_window. Falls back to shallow `from` only for the first pages.
    if search_after:
        body["search_after"] = search_after
    else:
        # Shallow `from` paging only works inside the 10k max_result_window.
        # Beyond it, reject loudly instead of silently clamping `from` (which
        # used to make every page past the window repeat the same last page).
        if page * size + size > MAX_RESULT_WINDOW:
            raise SearchError(
                f"page {page} with size {size} exceeds the {MAX_RESULT_WINDOW}-result "
                "window — use search_after cursor pagination (next_search_after) "
                "to page deeper"
            )
        # `size` is already in `body`; only the clamped `from` is needed here.
        body["from"] = paginate(page, size)["from"]

    try:
        result = _request("POST", f"/{index}/_search", body)
        return result
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            # Case has no indices yet — a legitimate empty result.
            return {"hits": {"total": {"value": 0}, "hits": []}}
        if exc.code == 400:
            reason = _es_error_reason(exc)
            if _is_missing_index(exc, reason):
                return {"hits": {"total": {"value": 0}, "hits": []}}
            # A rejected query is a broken query, not "0 results" — surface it.
            raise SearchError(f"Elasticsearch rejected the search query: {reason}") from exc
        raise


def _iso_to_epoch_ms(ts: str | None) -> int | None:
    """Parse an ISO8601 timestamp (Z or offset) to epoch milliseconds, or None."""
    if not ts:
        return None
    from datetime import datetime

    try:
        s = ts.replace("Z", "+00:00")
        return int(datetime.fromisoformat(s).timestamp() * 1000)
    except (ValueError, TypeError):
        return None


def _merge_term_buckets(aggs: list[dict], size: int) -> list[dict]:
    """Merge several same-purpose terms aggs (multi-field facet) into a single
    bucket list: doc_count summed per key, sorted desc, capped at ``size``."""
    merged: dict[Any, int] = {}
    for agg in aggs:
        for b in agg.get("buckets", []):
            merged[b["key"]] = merged.get(b["key"], 0) + b.get("doc_count", 0)
    return [
        {"key": k, "doc_count": c}
        for k, c in sorted(merged.items(), key=lambda kv: -kv[1])[:size]
    ]


# Painless script backing the unified severity sort (`_severity` sort field):
# level_int when present, otherwise text levels mapped to 1-5.
_SEVERITY_SORT_SCRIPT = (
    "if (doc.containsKey('hayabusa.level_int') && !doc['hayabusa.level_int'].empty) "
    "  return doc['hayabusa.level_int'].value; "
    "if (doc.containsKey('severity_int') && !doc['severity_int'].empty) "
    "  return doc['severity_int'].value; "
    "if (doc.containsKey('level_int') && !doc['level_int'].empty) "
    "  return doc['level_int'].value; "
    "def t = null; "
    "if (doc.containsKey('evtx.level') && !doc['evtx.level'].empty) t = doc['evtx.level'].value; "
    "else if (doc.containsKey('hayabusa.level') && !doc['hayabusa.level'].empty) t = doc['hayabusa.level'].value; "
    "else if (doc.containsKey('detection.level') && !doc['detection.level'].empty) t = doc['detection.level'].value; "
    "else if (doc.containsKey('level') && !doc['level'].empty) t = doc['level'].value; "
    "else if (doc.containsKey('severity') && !doc['severity'].empty) t = doc['severity'].value; "
    "if (t == null) return 0; "
    "t = t.toString().toLowerCase(); "
    "if (t.contains('crit')) return 5; "
    "if (t.contains('high') || t.contains('error') || t.contains('err')) return 4; "
    "if (t.contains('med') || t.contains('warn')) return 3; "
    "if (t.contains('low')) return 2; "
    "return 1;"
)


def get_search_facets(
    case_id: str,
    query: str = "",
    artifact_type: str | None = None,
    from_ts: str | None = None,
    to_ts: str | None = None,
) -> dict[str, Any]:
    """Return aggregation buckets for the facet panel.

    Activity histogram:
      • No range → ``auto_date_histogram`` over the whole case (ES picks interval).
      • Range set (zoomed) → a fixed-interval ``date_histogram`` whose interval is
        (to-from)/N and whose ``extended_bounds`` span the EXACT selected window,
        so the bars fill the selection edge-to-edge (including empty buckets)
        instead of only where data happens to land.
    """
    index = build_index_expression(case_id, artifact_type)

    must = (
        [
            {
                "query_string": {
                    # Same slash-escaping search_events applies — a stray '/'
                    # otherwise turns the facet query into an unparseable Lucene
                    # regexp and ES 400s the whole panel.
                    "query": escape_lucene_query(query, preserve_regex=True),
                    "fields": _SEARCH_FIELDS,
                    "max_determinized_states": _MAX_DETERMINIZED_STATES,
                }
            }
        ]
        if query
        else [{"match_all": {}}]
    )
    from_ms = _iso_to_epoch_ms(from_ts)
    to_ms = _iso_to_epoch_ms(to_ts)
    if from_ts or to_ts:
        rng = {}
        if from_ts:
            rng["gte"] = from_ts
        if to_ts:
            rng["lt"] = to_ts
        must.append({"range": {"timestamp": rng}})

    _TARGET_BUCKETS = 80
    if from_ms is not None and to_ms is not None and to_ms > from_ms:
        interval_ms = max(1, (to_ms - from_ms) // _TARGET_BUCKETS)
        events_over_time = {
            "date_histogram": {
                "field": "timestamp",
                "fixed_interval": f"{interval_ms}ms",
                "min_doc_count": 0,  # keep empty buckets so the window is full
                "extended_bounds": {"min": from_ms, "max": to_ms - 1},
            }
        }
    else:
        events_over_time = {"auto_date_histogram": {"field": "timestamp", "buckets": _TARGET_BUCKETS}}

    body = {
        "query": {"bool": {"must": must}},
        "size": 0,
        "aggs": {
            "by_artifact_type": {"terms": {"field": "artifact_type", "size": 20}},
            "by_hostname": {"terms": {"field": "host.hostname.keyword", "size": 20}},
            "by_username": {"terms": {"field": "user.name.keyword", "size": 20}},
            "by_event_id": {"terms": {"field": "evtx.event_id", "size": 30}},
            # evtx.channel / http.method are plain keywords in the template —
            # there is NO .keyword sub-field to aggregate on.
            "by_channel": {"terms": {"field": "evtx.channel", "size": 20}},
            # Network / web facets — empty (and hidden) for evtx-only cases, but
            # make the filter panel useful for access-log / network data.
            "by_src_ip": {"terms": {"field": "network.src_ip", "size": 20}},
            "by_dest_ip": {"terms": {"field": "network.dst_ip", "size": 20}},
            "by_status_code": {"terms": {"field": "http.status_code", "size": 20}},
            "by_http_method": {"terms": {"field": "http.method", "size": 10}},
            # One terms agg per real DNS-name field; merged into by_domain below.
            "by_domain__pcap": {"terms": {"field": "dns.query_name.keyword", "size": 20}},
            "by_domain__suricata": {"terms": {"field": "suricata.dns.rrname.keyword", "size": 20}},
            "by_domain__zeek": {"terms": {"field": "zeek.query.keyword", "size": 20}},
            "events_over_time": events_over_time,
        },
    }

    try:
        result = _request("POST", f"/{index}/_search", body)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        if exc.code == 400:
            reason = _es_error_reason(exc)
            if _is_missing_index(exc, reason):
                return {}
            # Consistent with search_events: a rejected query is an error,
            # not an empty facet panel.
            raise SearchError(f"Elasticsearch rejected the facet query: {reason}") from exc
        raise
    aggs = result.get("aggregations", {})
    aggs["by_domain"] = {
        "buckets": _merge_term_buckets(
            [
                aggs.pop("by_domain__pcap", {}),
                aggs.pop("by_domain__suricata", {}),
                aggs.pop("by_domain__zeek", {}),
            ],
            size=20,
        )
    }
    return aggs


def get_event_by_id(case_id: str, fo_id: str) -> dict | None:
    """Fetch a single event by its fo_id."""
    body = {
        "query": {"term": {"fo_id": fo_id}},
        "size": 1,
    }
    try:
        result = _request("POST", f"/fo-case-{case_id}-*/_search", body)
        hits = result.get("hits", {}).get("hits", [])
        if hits:
            return {"_id": hits[0]["_id"], "_index": hits[0]["_index"], **hits[0]["_source"]}
        return None
    except Exception:
        return None


def update_event(case_id: str, index: str, doc_id: str, partial: dict) -> bool:
    """Partially update an event document."""
    try:
        _request("POST", f"/{index}/_update/{doc_id}", {"doc": partial})
        return True
    except Exception:
        return False


_ARTIFACTS_INDEX = "fo-artifacts"

_ARTIFACTS_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "case_id": {"type": "keyword"},
            "job_id": {"type": "keyword"},
            "filename": {"type": "keyword"},
            "plugin_used": {"type": "keyword"},
            "mime_type": {"type": "keyword"},
            "events_indexed": {"type": "integer"},
            "skipped": {"type": "boolean"},
            "minio_key": {"type": "keyword", "index": False},
            "completed_at": {"type": "date"},
        }
    },
}


def ensure_artifacts_index() -> None:
    try:
        _request("GET", f"/{_ARTIFACTS_INDEX}")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            try:
                _request("PUT", f"/{_ARTIFACTS_INDEX}", _ARTIFACTS_MAPPING)
                logger.info("Created %s index", _ARTIFACTS_INDEX)
            except Exception as create_exc:
                logger.warning("Could not create artifacts index: %s", create_exc)


def index_artifact(doc: dict) -> None:
    job_id = doc.get("job_id", "unknown")
    try:
        _request("PUT", f"/{_ARTIFACTS_INDEX}/_doc/{job_id}", doc)
    except Exception as exc:
        logger.warning("Failed to index artifact %s: %s", job_id, exc)


def list_case_artifacts(case_id: str, size: int = 5000) -> list[dict]:
    body = {
        "query": {"term": {"case_id": case_id}},
        "size": size,
        "sort": [{"completed_at": {"order": "desc"}}],
    }
    try:
        result = _request("POST", f"/{_ARTIFACTS_INDEX}/_search", body)
        return [h["_source"] for h in result.get("hits", {}).get("hits", [])]
    except Exception:
        return []


def search_events_for_rule(case_id: str, query: str, size: int = 10) -> list[dict]:
    """Run a Lucene query against a case and return the first N hits (for Studio rule playground)."""
    index = f"fo-case-{case_id}-*"
    body = {
        "query": {
            "query_string": {
                "query": escape_lucene_query(query, preserve_regex=True),
                "default_operator": "AND",
                "fields": ["*"],
                "allow_leading_wildcard": True,
                "analyze_wildcard": True,
                "max_determinized_states": _MAX_DETERMINIZED_STATES,
            }
        },
        "size": size,
        "sort": [{"timestamp": {"order": "asc"}}],
        "_source": {"excludes": ["raw.xml"]},
    }
    try:
        result = _request("POST", f"/{index}/_search", body)
        return [h["_source"] for h in result.get("hits", {}).get("hits", [])]
    except Exception:
        return []


def delete_case_indices(case_id: str) -> None:
    """Delete all indices for a case."""
    indices = list_case_indices(case_id)
    if not indices:
        logger.info("No indices found for case %s", case_id)
        return
    index_list = ",".join(indices)
    try:
        _request("DELETE", f"/{index_list}")
        logger.info("Deleted %d indices for case %s", len(indices), case_id)
    except Exception as exc:
        logger.warning("Error deleting case %s indices: %s", case_id, exc)
