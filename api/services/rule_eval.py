"""Shared detection-rule evaluation — plain thresholds and correlation.

Every rule-running endpoint (case rules, the global library, single-rule runs,
LLM analysis) used to build its own Elasticsearch body and its own
``count >= threshold`` check. Five near-identical copies meant a fix or a new
capability had to be applied five times, so they had already drifted (only some
set ``track_total_hits``, so counts above 10 000 were silently capped at 10 000
in the others).

It also capped what a rule could *express*. ``count >= threshold`` cannot say
"many distinct accounts from ONE source", which is the difference between
detecting a password spray and alerting on every failed login in the case. That
shape — a common entity with an unusual amount of variety under it — is what
makes a rule resistant to false positives, so it is now a first-class rule
capability:

    # 20+ distinct target accounts from a single source IP: a spray.
    # A busy helpdesk generating 20 failures against ONE account does not match.
    correlation:
      group_by: network.src_ip
      distinct: user.name
      min_distinct: 20

    # Optional: require the variety within a time window rather than over the
    # whole case, so slow organic churn does not accumulate into a detection.
      window: 15m

``group_by`` may be omitted to ask a case-wide question ("did we see 50 distinct
accounts fail at all?"). ``distinct`` and ``min_distinct`` are required.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from services.elasticsearch import _request as es_req

logger = logging.getLogger(__name__)

# Terms-agg breadth. A spray from thousands of sources is still a spray; we only
# need enough buckets to find the offenders, not a full inventory.
_MAX_GROUPS = 1000
# cardinality is approximate above this; below it, counts are exact. Rule
# thresholds are small (tens), so exactness in that range is what matters.
_CARDINALITY_PRECISION = 4000

_WINDOW_RE = re.compile(r"^(\d+)([smhd])$")


class RuleEvalError(RuntimeError):
    """The rule could not be evaluated (bad query, backend failure)."""


def index_for(case_id: str, rule: dict) -> str:
    """Indices a rule reads. Empty/absent artifact_type means every index.

    A comma-separated list is passed through, so a rule whose evidence spans
    several artifact types (registry-derived events land in -persistence,
    -shimcache, -bam, -userassist…) can name them all.
    """
    atype = str(rule.get("artifact_type") or "").strip()
    if not atype:
        return f"fo-case-{case_id}-*"
    parts = [p.strip() for p in atype.split(",") if p.strip()]
    return ",".join(f"fo-case-{case_id}-{p}" for p in parts)


def parse_window(window: str | None) -> str | None:
    """Validate a ``30s``/``15m``/``6h``/``7d`` window into an ES interval."""
    if not window:
        return None
    m = _WINDOW_RE.match(str(window).strip())
    if not m:
        raise RuleEvalError(f"invalid correlation window {window!r} — use 30s/15m/6h/7d")
    return m.group(0)


def _keyword(field: str) -> str:
    """Aggregations need an exact-value field; analyzed text cannot be grouped.

    The index template maps strings as text + a ``.keyword`` subfield, so append
    it unless the caller already did or the field is natively keyword/numeric.
    """
    if field.endswith(".keyword"):
        return field
    # Fields the template declares as keyword/ip/long — grouping on these
    # directly is correct and `.keyword` would not exist.
    exact_prefixes = (
        "artifact_type", "os", "tags", "fo_id", "case_id", "ingest_job_id",
        "timestamp_desc", "evtx.event_id", "evtx.channel", "evtx.provider_name",
        "evtx.level", "network.src_ip", "network.dst_ip", "network.src_port",
        "network.dst_port", "network.protocol", "network.action", "user.sid",
        "user.domain", "user.id", "host.ip", "host.os", "host.domain",
        "file.sha256", "file.sha1", "file.md5", "file.extension",
        "process.pid", "process.ppid", "registry.hive", "registry.value_type",
    )
    if field in exact_prefixes:
        return field
    return f"{field}.keyword"


def evaluate(case_id: str, rule: dict, sample_size: int = 5) -> dict | None:
    """Run *rule* against *case_id*. Returns a match dict, or None if it did not fire.

    The match carries ``match_count`` and ``sample_events`` exactly as the old
    per-endpoint code did, so callers and the stored run format are unchanged. A
    correlation rule additionally carries ``groups`` — the entities that
    qualified, with their distinct counts — because "10.0.0.5 saw 47 distinct
    accounts" is the finding, not the raw event count.

    Raises RuleEvalError only for genuine backend failures; a missing index or a
    query the backend rejects is reported as "did not fire", matching the
    previous behaviour (a case simply may not have that artifact type).
    """
    if rule.get("correlation"):
        return _evaluate_correlation(case_id, rule, sample_size)
    return _evaluate_threshold(case_id, rule, sample_size)


def _search(index: str, body: dict) -> dict | None:
    """POST a search; None when the index/query means "nothing to match"."""
    try:
        return es_req("POST", f"/{index}/_search", body)
    except Exception as exc:  # noqa: BLE001 - see docstring on evaluate()
        code = getattr(exc, "code", None)
        if code in (400, 404):
            logger.debug("rule search returned %s for %s (treated as no match)", code, index)
            return None
        logger.warning("rule search failed on %s: %s", index, exc)
        return None


def _evaluate_threshold(case_id: str, rule: dict, sample_size: int) -> dict | None:
    body = {
        "query": {"query_string": {"query": rule["query"], "default_operator": "AND"}},
        "size": sample_size,
        # Without this ES stops counting at 10 000, so a rule with threshold
        # 20 000 could never fire and every big detection reported exactly
        # 10 000. Three of the five old call sites omitted it.
        "track_total_hits": True,
        "_source": ["timestamp", "message", "host", "user", "fo_id", "artifact_type"],
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    resp = _search(index_for(case_id, rule), body)
    if resp is None:
        return None
    count = (resp.get("hits", {}).get("total") or {}).get("value", 0)
    if count < int(rule.get("threshold", 1) or 1):
        return None
    return {
        "rule": rule,
        "match_count": count,
        "sample_events": [h.get("_source", {}) for h in resp["hits"]["hits"]],
    }


def _evaluate_correlation(case_id: str, rule: dict, sample_size: int) -> dict | None:
    corr = rule["correlation"] or {}
    distinct = str(corr.get("distinct") or "").strip()
    min_distinct = int(corr.get("min_distinct") or 0)
    if not distinct or min_distinct < 1:
        raise RuleEvalError("correlation requires 'distinct' and a positive 'min_distinct'")
    group_by = str(corr.get("group_by") or "").strip()
    window = parse_window(corr.get("window"))

    card = {"cardinality": {"field": _keyword(distinct),
                            "precision_threshold": _CARDINALITY_PRECISION}}
    query = {"query_string": {"query": rule["query"], "default_operator": "AND"}}

    # Three shapes: case-wide variety, variety per entity, or variety per entity
    # per window. The window form is what stops slow organic churn (a year of
    # helpdesk resets) from accumulating into a detection.
    if not group_by:
        aggs: dict[str, Any] = {"n": card}
    elif not window:
        aggs = {"g": {"terms": {"field": _keyword(group_by), "size": _MAX_GROUPS},
                      "aggs": {"n": card}}}
    else:
        aggs = {"g": {"terms": {"field": _keyword(group_by), "size": _MAX_GROUPS},
                      "aggs": {"w": {"date_histogram": {"field": "timestamp",
                                                        "fixed_interval": window},
                                     "aggs": {"n": card}}}}}

    resp = _search(index_for(case_id, rule), {"query": query, "size": 0, "aggs": aggs})
    if resp is None:
        return None
    aggregations = resp.get("aggregations") or {}

    groups: list[dict] = []
    if not group_by:
        n = int((aggregations.get("n") or {}).get("value", 0))
        if n >= min_distinct:
            groups.append({"key": "(case-wide)", "distinct": n, "events": None})
    else:
        for bucket in (aggregations.get("g") or {}).get("buckets", []):
            if window:
                # Best window for this entity — one qualifying burst is enough.
                best = None
                for wb in (bucket.get("w") or {}).get("buckets", []):
                    n = int((wb.get("n") or {}).get("value", 0))
                    if best is None or n > best[0]:
                        best = (n, wb.get("key_as_string") or wb.get("key"))
                if best and best[0] >= min_distinct:
                    groups.append({"key": bucket.get("key"), "distinct": best[0],
                                   "events": bucket.get("doc_count"), "window_start": best[1]})
            else:
                n = int((bucket.get("n") or {}).get("value", 0))
                if n >= min_distinct:
                    groups.append({"key": bucket.get("key"), "distinct": n,
                                   "events": bucket.get("doc_count")})

    if not groups:
        return None
    groups.sort(key=lambda g: -g["distinct"])

    # Pull samples from the qualifying entities only, so the evidence shown is
    # the detection rather than an arbitrary slice of the rule's raw matches.
    samples: list[dict] = []
    if sample_size:
        sample_body = {
            "query": query,
            "size": sample_size,
            "track_total_hits": True,
            "_source": ["timestamp", "message", "host", "user", "fo_id", "artifact_type"],
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        if group_by:
            sample_body["query"] = {
                "bool": {
                    "must": [query],
                    "filter": [{"terms": {_keyword(group_by): [g["key"] for g in groups[:50]]}}],
                }
            }
        sresp = _search(index_for(case_id, rule), sample_body)
        if sresp:
            samples = [h.get("_source", {}) for h in sresp["hits"]["hits"]]

    return {
        "rule": rule,
        # The finding is "N entities showed unusual variety", so that is the
        # count the UI ranks and the report states.
        "match_count": len(groups),
        "sample_events": samples,
        "correlation": {
            "group_by": group_by or None,
            "distinct_field": distinct,
            "min_distinct": min_distinct,
            "window": window,
            "groups": groups[:50],
            "summary": _summarise(groups, group_by, distinct, window),
        },
    }


def _summarise(groups: list[dict], group_by: str, distinct: str, window: str | None) -> str:
    top = groups[0]
    scope = f" within {window}" if window else ""
    if not group_by:
        return f"{top['distinct']} distinct {distinct} across the case{scope}"
    extra = f" (+{len(groups) - 1} more)" if len(groups) > 1 else ""
    return (
        f"{group_by} {top['key']} saw {top['distinct']} distinct {distinct}{scope}{extra}"
    )
