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

import hashlib
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
    """POST a search. None means "legitimately nothing to match".

    A 404 (or a missing-index 400) is normal: a case simply may not hold that
    artifact type. A query Elasticsearch REJECTS is not — it is a broken rule,
    and reporting it as "no match" is how a rule that 400s on every run stays
    indistinguishable from one that found nothing. Several rules had been dead
    that way for a long time (an unescaped ``/`` makes query_string read
    ``/.../`` as a regex; an unescaped ``:`` is the field separator; a quote or
    bracket inside a wildcard is rejected outright), so a malformed query now
    raises instead of vanishing.
    """
    try:
        return es_req("POST", f"/{index}/_search", body)
    except Exception as exc:  # noqa: BLE001 - classified below
        code = getattr(exc, "code", None)
        text = str(exc)
        if code == 404 or "index_not_found" in text:
            logger.debug("rule search: no index %s (no match)", index)
            return None
        if code == 400:
            if "no such index" in text or "index_not_found" in text:
                return None
            raise RuleEvalError(
                f"Elasticsearch rejected the rule query — the rule cannot ever "
                f"match and needs fixing: {text[:300]}"
            ) from exc
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


# ── Cooldown (detection dedup) ────────────────────────────────────────────────
# The same rule firing on the same entity over and over is the top source of
# alert fatigue. After a rule fires, a marker is recorded in Redis per
# (case, rule, entity) with the match signature; an identical match inside the
# cooldown window is counted as suppressed instead of refiring (new detection
# event, webhook, …). A NEW signature — different samples for a threshold rule,
# a different group key for a correlation rule — fires normally.
#
# The marker key is built here rather than in redis_keys.py so the worker port
# (tools/sluice/worker/rule_eval.py) can construct the identical key string —
# both sides must agree on it byte-for-byte.

DEFAULT_COOLDOWN_MINUTES = 60.0


def cooldown_minutes_for(rule: dict) -> float:
    """Effective cooldown in minutes: per-rule override, default 60.

    ``cooldown_minutes`` absent/zero/invalid → the default. Fractional values
    are accepted (mainly so tests can use sub-second windows).
    """
    try:
        v = float(rule.get("cooldown_minutes") or 0)
    except (TypeError, ValueError):
        v = 0
    return v if v > 0 else DEFAULT_COOLDOWN_MINUTES


def cooldown_key(case_id: str, rule_id: str, entity_key: str) -> str:
    """Redis marker key for one (case, rule, entity) cooldown entry."""
    digest = hashlib.sha256(entity_key.encode("utf-8", "replace")).hexdigest()[:24]
    return f"fo:alert_cooldown:{case_id}:{rule_id}:{digest}"


def _entities_with_signatures(match: dict) -> list[tuple[str, str]]:
    """(entity_key, signature) pairs identifying WHAT a fired match hit.

    Correlation rule → one pair per qualifying group; the group key is both the
    entity and the signature (the same entity re-qualifying is the dup we
    suppress). Threshold rule → a single "case" entity whose signature is a
    hash of the sorted sample fo_ids, so the same evidence refiring is
    suppressed while genuinely new samples fire.
    """
    corr = match.get("correlation") or {}
    groups = corr.get("groups") or []
    if groups:
        return [(str(g.get("key") or "case"),) * 2 for g in groups]
    fo_ids = sorted(
        str(ev["fo_id"]) for ev in match.get("sample_events", []) if ev.get("fo_id")
    )
    sig_src = "|".join(fo_ids) if fo_ids else f"count:{match.get('match_count', 0)}"
    return [("case", hashlib.sha256(sig_src.encode()).hexdigest())]


def evaluate_with_cooldown(case_id: str, rule: dict, r=None, sample_size: int = 5) -> dict | None:
    """evaluate() plus cooldown dedup — the entry point run paths should use.

    Returns None when the rule did not match at all. A firing match carries:
      - ``suppressed_count`` / ``suppressed_entities`` — how much of the match
        was already known inside the cooldown window;
      - ``cooldown_minutes`` — the window that was applied;
      - ``suppressed_only: True`` when EVERY entity matched is inside its
        cooldown: the caller must persist it in the run record (so the UI can
        show "12 suppressed (cooldown)") but must NOT index a detection event
        or fire a webhook for it.
    A correlation match that is partially new is narrowed to the new entities.

    Redis failures fail OPEN: a flaky Redis must never drop a detection.
    """
    match = evaluate(case_id, rule, sample_size)
    if match is None:
        return None
    match["suppressed_count"] = 0
    match["suppressed_entities"] = []
    match["cooldown_minutes"] = cooldown_minutes_for(rule)
    if r is None:
        return match
    try:
        return _apply_cooldown(r, case_id, rule, match)
    except Exception:  # noqa: BLE001 - cooldown is best-effort, detection is not
        logger.warning(
            "cooldown check failed for rule %r on case %s — firing anyway",
            rule.get("name"), case_id,
        )
        return match


def _apply_cooldown(r, case_id: str, rule: dict, match: dict) -> dict:
    rule_id = str(rule.get("id") or rule.get("name") or "")
    # int() truncation plus the 1s floor keeps sub-minute test windows usable.
    ttl = max(1, int(cooldown_minutes_for(rule) * 60))
    entities = _entities_with_signatures(match)
    keys = [cooldown_key(case_id, rule_id, entity_key) for entity_key, _ in entities]

    pipe = r.pipeline(transaction=False)
    for key in keys:
        pipe.get(key)
    markers = pipe.execute()

    new: list[tuple[str, str]] = []
    suppressed: list[str] = []
    for (entity_key, sig), marker in zip(entities, markers, strict=True):
        if isinstance(marker, bytes):
            marker = marker.decode()
        if marker is not None and marker == sig:
            suppressed.append(entity_key)
        else:
            new.append((entity_key, sig))

    if new:
        # Fixed window from the last FIRE — suppressed hits do not extend it,
        # so a persistent condition re-alerts once per cooldown, not never.
        pipe = r.pipeline(transaction=False)
        for entity_key, sig in new:
            pipe.set(cooldown_key(case_id, rule_id, entity_key), sig, ex=ttl)
        pipe.execute()

    if suppressed:
        match["suppressed_count"] = len(suppressed)
        match["suppressed_entities"] = suppressed[:20]

    if not new:
        match["suppressed_only"] = True
        match["match_count"] = 0  # 0 NEW — the raw count is stale evidence
        match["sample_events"] = []
        return match

    corr = match.get("correlation")
    if corr and corr.get("groups") and suppressed:
        new_keys = {entity_key for entity_key, _ in new}
        groups = [g for g in corr["groups"] if str(g.get("key") or "case") in new_keys]
        corr["groups"] = groups[:50]
        match["match_count"] = len(groups)
        corr["summary"] = _summarise(
            groups, corr.get("group_by") or "", corr.get("distinct_field") or "",
            corr.get("window"),
        )
    return match
