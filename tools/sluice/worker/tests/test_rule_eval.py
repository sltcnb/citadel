"""Tests for the worker-side detection-rule evaluation port and auto-run fixes.

Covers the parity work between tools/sluice/worker (rule_eval.py +
tasks/ingest_task.py) and the API reference (api/services/rule_eval.py,
api/services/sigma_settings.py):

  * correlation rules fire only when min_distinct is met (terms + cardinality
    aggs, optional date_histogram window) — never on raw count >= threshold;
  * index_for() expands comma-separated artifact_type and rejects values that
    could escape the case's indices (cross-tenant guard);
  * the Sigma opt-out (per-case override / global runtime key) is honored by
    the worker auto-run;
  * every rule/watchlist search carries track_total_hits (no 10 000 cap);
  * rule_severity falls back level → sigma_level → severity → "medium";
  * the persisted run record keeps prior LLM analyses and lists per-rule errors;
  * the detection debounce lock covers the countdown and chain hops re-acquire
    (and release) it by token.
"""

from __future__ import annotations

import json
import urllib.error

import pytest
import rule_eval
from tasks import ingest_task


class FakeRedis:
    """In-memory Redis stand-in with real SET NX semantics (the debounce lock
    tests depend on nx actually being honored)."""

    def __init__(self) -> None:
        self.kv: dict[str, str] = {}
        self.hashes: dict[str, dict] = {}
        self.expires: dict[str, int] = {}

    def get(self, key):
        return self.kv.get(key)

    def set(self, key, value, ex=None, nx=False, **kwargs):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        if ex is not None:
            self.expires[key] = ex
        return True

    def delete(self, key):
        self.kv.pop(key, None)
        return 1

    def expire(self, key, ttl):
        self.expires[key] = ttl
        return True

    def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    def hset(self, key, field=None, value=None, mapping=None):
        h = self.hashes.setdefault(key, {})
        if mapping:
            h.update(mapping)
        if field is not None:
            h[field] = value
        return 1

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))


# ── rule_severity ─────────────────────────────────────────────────────────────


def test_rule_severity_fallback_order():
    assert rule_eval.rule_severity({"level": "high"}) == "high"
    assert rule_eval.rule_severity({"sigma_level": "critical"}) == "critical"
    assert rule_eval.rule_severity({"severity": "low"}) == "low"
    # `level` wins over sigma_level; sigma_level wins over severity.
    assert rule_eval.rule_severity({"level": "high", "sigma_level": "low"}) == "high"
    assert rule_eval.rule_severity({"sigma_level": "high", "severity": "low"}) == "high"
    assert rule_eval.rule_severity({}) == "medium"
    assert rule_eval.rule_severity({"level": "HIGH"}) == "high"
    # Empty strings are falsy — fall through.
    assert rule_eval.rule_severity({"level": "", "sigma_level": "medium"}) == "medium"


# ── index_for (comma artifact_type + cross-tenant guard) ──────────────────────


def test_index_for_empty_is_case_wildcard():
    assert rule_eval.index_for("c1", {}) == "fo-case-c1-*"
    assert rule_eval.index_for("c1", {"artifact_type": ""}) == "fo-case-c1-*"
    assert rule_eval.index_for("c1", {"artifact_type": "*"}) == "fo-case-c1-*"


def test_index_for_comma_list_expands_to_multiple_indices():
    rule = {"artifact_type": "persistence,shimcache"}
    assert rule_eval.index_for("c1", rule) == "fo-case-c1-persistence,fo-case-c1-shimcache"


def test_index_for_rejects_cross_tenant_values():
    for bad in ("x,fo-case-victim-*", "../other", "Persistence", "a b", "a,*"):
        with pytest.raises(rule_eval.RuleEvalError):
            rule_eval.index_for("c1", {"artifact_type": bad})


# ── threshold evaluation ──────────────────────────────────────────────────────


def _hits(total, samples=None):
    return {"hits": {"total": {"value": total}, "hits": samples or []}}


def test_threshold_sends_track_total_hits_and_index():
    calls = []

    def search(index, body):
        calls.append((index, body))
        return _hits(3)

    rule = {"name": "r", "query": "x:y", "threshold": 2, "artifact_type": "evtx"}
    match = rule_eval.evaluate("c1", rule, search=search)
    assert match is not None and match["match_count"] == 3
    index, body = calls[0]
    assert index == "fo-case-c1-evtx"
    assert body["track_total_hits"] is True


def test_threshold_below_does_not_fire():
    rule = {"name": "r", "query": "x:y", "threshold": 5}
    assert rule_eval.evaluate("c1", rule, search=lambda i, b: _hits(4)) is None


def test_missing_index_is_no_match_not_error():
    rule = {"name": "r", "query": "x:y"}
    assert rule_eval.evaluate("c1", rule, search=lambda i, b: None) is None


# ── correlation evaluation ────────────────────────────────────────────────────

_CORR_RULE = {
    "name": "Password Spray",
    "query": "evtx.event_id:4625",
    "artifact_type": "evtx",
    "correlation": {
        "group_by": "network.src_ip",
        "distinct": "user.name",
        "min_distinct": 20,
    },
}


def _corr_aggs(buckets):
    return {
        "aggregations": {
            "g": {
                "buckets": [
                    {"key": k, "doc_count": dc, "n": {"value": n}} for k, dc, n in buckets
                ]
            }
        }
    }


def test_correlation_fires_only_when_min_distinct_met():
    # 100 raw events but every source stays under min_distinct → no match,
    # even though count >= any sane threshold.
    def search_under(index, body):
        if body.get("aggs"):
            return _corr_aggs([("10.0.0.5", 100, 19), ("10.0.0.6", 100, 12)])
        return _hits(0)

    assert rule_eval.evaluate("c1", dict(_CORR_RULE), search=search_under) is None

    # One source over min_distinct → fires; match_count counts qualifying
    # ENTITIES, not raw events.
    def search_over(index, body):
        if body.get("aggs"):
            return _corr_aggs([("10.0.0.5", 47, 47), ("10.0.0.6", 30, 3)])
        return _hits(2, [{"_source": {"message": "m1"}}, {"_source": {"message": "m2"}}])

    match = rule_eval.evaluate("c1", dict(_CORR_RULE), search=search_over)
    assert match is not None
    assert match["match_count"] == 1
    groups = match["correlation"]["groups"]
    assert groups == [{"key": "10.0.0.5", "distinct": 47, "events": 47}]
    assert "10.0.0.5 saw 47 distinct user.name" in match["correlation"]["summary"]
    assert len(match["sample_events"]) == 2


def test_correlation_agg_query_uses_keyword_fields_and_index():
    calls = []

    def search(index, body):
        calls.append((index, body))
        return _corr_aggs([])

    rule_eval.evaluate("c1", dict(_CORR_RULE), search=search)
    index, body = calls[0]
    assert index == "fo-case-c1-evtx"
    terms = body["aggs"]["g"]["terms"]
    assert terms["field"] == "network.src_ip"  # natively exact — no .keyword
    card = body["aggs"]["g"]["aggs"]["n"]["cardinality"]
    assert card["field"] == "user.name.keyword"  # analyzed text → .keyword
    # Samples are pulled only from qualifying entities (second call, if any).
    assert len(calls) == 1  # no groups → no sample query


def test_correlation_window_uses_date_histogram():
    calls = []

    def search(index, body):
        calls.append(body)
        if body.get("aggs"):
            return {
                "aggregations": {
                    "g": {
                        "buckets": [
                            {
                                "key": "10.0.0.5",
                                "doc_count": 50,
                                "w": {
                                    "buckets": [
                                        {"key_as_string": "t0", "n": {"value": 5}},
                                        {"key_as_string": "t1", "n": {"value": 25}},
                                    ]
                                },
                            }
                        ]
                    }
                }
            }
        return _hits(0)

    rule = dict(_CORR_RULE)
    rule["correlation"] = dict(_CORR_RULE["correlation"], window="15m")
    match = rule_eval.evaluate("c1", rule, search=search)
    hist = calls[0]["aggs"]["g"]["aggs"]["w"]["date_histogram"]
    assert hist == {"field": "timestamp", "fixed_interval": "15m"}
    assert match is not None
    grp = match["correlation"]["groups"][0]
    # Best window wins; a single qualifying burst is enough.
    assert grp["distinct"] == 25 and grp["window_start"] == "t1"


def test_correlation_requires_distinct_and_min_distinct():
    rule = {"name": "bad", "query": "q", "correlation": {"group_by": "host.ip"}}
    with pytest.raises(rule_eval.RuleEvalError):
        rule_eval.evaluate("c1", rule, search=lambda i, b: None)


def test_parse_window_validation():
    assert rule_eval.parse_window(None) is None
    assert rule_eval.parse_window("15m") == "15m"
    with pytest.raises(rule_eval.RuleEvalError):
        rule_eval.parse_window("soon")


# ── Sigma opt-out ─────────────────────────────────────────────────────────────


def test_sigma_enabled_for_case_precedence():
    r = FakeRedis()
    # Default: nothing set → env default (true in test env).
    assert rule_eval.sigma_enabled_for_case(r, "c1") is True
    # Global runtime off → disabled.
    r.set("fo:settings:sigma_enabled", "0")
    assert rule_eval.sigma_enabled_for_case(r, "c1") is False
    # Per-case override beats the global setting.
    r.hset("case:c1", "sigma_enabled", "1")
    assert rule_eval.sigma_enabled_for_case(r, "c1") is True
    r.hset("case:c1", "sigma_enabled", "0")
    assert rule_eval.sigma_enabled_for_case(r, "c1") is False


def test_is_sigma_rule():
    assert rule_eval.is_sigma_rule({"rule_type": "sigma"})
    assert rule_eval.is_sigma_rule({"sigma_yaml": "title: x"})
    assert not rule_eval.is_sigma_rule({"rule_type": "custom"})
    assert not rule_eval.is_sigma_rule({})


# ── _run_library_rules integration (mocked ES) ────────────────────────────────


def _patch_es(monkeypatch, handler):
    """Route rule_eval's ES calls through *handler(index, body)*."""
    monkeypatch.setattr(rule_eval, "_es_search", handler)
    monkeypatch.setattr(ingest_task, "_fire_alert_webhooks", lambda *a, **kw: None)


def _library(rules):
    return json.dumps(rules)


def test_run_library_rules_skips_sigma_when_opted_out(monkeypatch):
    rules = [
        {"id": "s1", "name": "Sigma Rule", "query": "a:b", "rule_type": "sigma"},
        {"id": "n1", "name": "Native Rule", "query": "a:b"},
    ]
    r = FakeRedis()
    r.set("fo:alert_rules:_global", _library(rules))
    r.hset("case:c1", "sigma_enabled", "0")

    searched = []

    def es(index, body):
        searched.append((index, body))
        return _hits(0)

    _patch_es(monkeypatch, es)
    ingest_task._run_library_rules(r, "c1")

    run = json.loads(r.get("fo:alert_run:c1"))
    assert run["rules_checked"] == 1
    # Only the native rule was searched; the sigma rule never hit ES.
    assert len(searched) == 1


def test_run_library_rules_runs_sigma_when_enabled(monkeypatch):
    rules = [{"id": "s1", "name": "Sigma Rule", "query": "a:b", "sigma_yaml": "title: x"}]
    r = FakeRedis()
    r.set("fo:alert_rules:_global", _library(rules))

    searched = []

    def es(index, body):
        searched.append((index, body))
        return _hits(0)

    _patch_es(monkeypatch, es)
    ingest_task._run_library_rules(r, "c1")
    assert len(searched) == 1


def test_run_library_rules_sends_track_total_hits_and_expands_comma_type(monkeypatch):
    rules = [
        {"id": "r1", "name": "Multi", "query": "a:b", "artifact_type": "persistence,shimcache"}
    ]
    r = FakeRedis()
    r.set("fo:alert_rules:_global", _library(rules))

    calls = []

    def es(index, body):
        calls.append((index, body))
        return _hits(0)

    _patch_es(monkeypatch, es)
    ingest_task._run_library_rules(r, "c1")

    index, body = calls[0]
    assert index == "fo-case-c1-persistence,fo-case-c1-shimcache"
    assert body["track_total_hits"] is True


def test_run_library_rules_records_errors_for_rejected_queries(monkeypatch):
    rules = [
        {"id": "bad", "name": "Broken Rule", "query": "a:("},
        {"id": "ok", "name": "Fine Rule", "query": "a:b"},
    ]
    r = FakeRedis()
    r.set("fo:alert_rules:_global", _library(rules))

    def es(index, body):
        if body["query"]["query_string"]["query"] == "a:(":
            raise urllib.error.HTTPError(
                "http://es", 400, "Bad Request: parse_exception", {}, None
            )
        return _hits(0)

    _patch_es(monkeypatch, es)
    ingest_task._run_library_rules(r, "c1")

    run = json.loads(r.get("fo:alert_run:c1"))
    assert run["rules_checked"] == 2
    assert run["matches"] == []
    assert len(run["errors"]) == 1
    assert run["errors"][0]["rule"] == "Broken Rule"
    assert "rejected" in run["errors"][0]["error"]


def test_run_library_rules_preserves_cached_analyses(monkeypatch):
    r = FakeRedis()
    r.set("fo:alert_rules:_global", _library([{"id": "r1", "name": "R", "query": "a:b"}]))
    r.set(
        "fo:alert_run:c1",
        json.dumps({"ran_at": "2024-01-01", "matches": [], "analyses": {"r1": {"verdict": "tp"}}}),
    )

    _patch_es(monkeypatch, lambda i, b: _hits(0))
    ingest_task._run_library_rules(r, "c1")

    run = json.loads(r.get("fo:alert_run:c1"))
    assert run["analyses"] == {"r1": {"verdict": "tp"}}
    assert run["errors"] == []


def test_detection_events_use_normalized_severity(monkeypatch):
    # Native sigil rule carrying `level` (not sigma_level) must report its real
    # severity in the detection timeline event and the webhook summary.
    rules = [{"id": "r1", "name": "Sigil Rule", "query": "a:b", "level": "high", "threshold": 1}]
    r = FakeRedis()
    r.set("fo:alert_rules:_global", _library(rules))

    indexed = []

    class _Idx:
        def __init__(self, url):
            pass

        def bulk_index(self, case_id, events):
            indexed.extend(events)

    monkeypatch.setattr(rule_eval, "_es_search", lambda i, b: _hits(1, [{"_source": {"timestamp": "t"}}]))
    monkeypatch.setattr(ingest_task, "ESBulkIndexer", _Idx)

    # Let the real _fire_alert_webhooks run; capture the payload at the
    # (lazily imported) delivery boundary.
    import tasks._webhooks as wh

    fired = []
    monkeypatch.setattr(wh, "fire_webhooks", lambda *a, **kw: fired.append((a, kw)))

    ingest_task._run_library_rules(r, "c1")

    assert indexed and indexed[0]["detection"]["level"] == "high"
    assert fired and fired[0][0][2]["matches"][0]["level"] == "high"


# ── watchlist sweep ───────────────────────────────────────────────────────────


def test_watchlist_sweep_sends_track_total_hits(monkeypatch):
    r = FakeRedis()
    r.hset("fo:watchlist", "e1", json.dumps({"id": "e1", "query": "evil.exe", "kind": "file"}))

    bodies = []

    def es(index, body):
        bodies.append((index, body))
        return {"hits": {"total": {"value": 3}}}

    monkeypatch.setattr(ingest_task, "_es_search", es)
    ingest_task._run_watchlist(r, "c1")

    assert bodies and bodies[0][1]["track_total_hits"] is True
    assert bodies[0][0] == "fo-case-c1-*"
    run = json.loads(r.get("fo:watchlist_runs:c1"))
    assert run["hits"][0]["hits"] == 3


# ── debounce lock / chain ─────────────────────────────────────────────────────


def test_auto_run_lock_ttl_covers_countdown(monkeypatch):
    r = FakeRedis()
    scheduled = []
    monkeypatch.setattr(
        ingest_task.maybe_run_detections,
        "apply_async",
        lambda *a, **kw: scheduled.append((a, kw)),
    )

    ingest_task._auto_run_alert_rules(r, "c1")

    lock_key = "fo:alert_run_lock:c1"
    assert r.expires[lock_key] == ingest_task._DETECTION_LOCK_TTL
    assert ingest_task._DETECTION_LOCK_TTL >= ingest_task._DETECTION_COUNTDOWN
    # The chain token is passed to the scheduled task.
    token = r.get(lock_key)
    assert token and scheduled[0][1]["kwargs"]["_token"] == token
    assert scheduled[0][1]["countdown"] == ingest_task._DETECTION_COUNTDOWN

    # Second completion while the lock is held → no duplicate chain.
    ingest_task._auto_run_alert_rules(r, "c1")
    assert len(scheduled) == 1


def test_auto_run_releases_lock_when_scheduling_fails(monkeypatch):
    r = FakeRedis()

    def boom(*a, **kw):
        raise RuntimeError("broker down")

    monkeypatch.setattr(ingest_task.maybe_run_detections, "apply_async", boom)
    ingest_task._auto_run_alert_rules(r, "c1")
    assert r.get("fo:alert_run_lock:c1") is None


def _patch_idle(monkeypatch, active):
    monkeypatch.setattr(ingest_task, "_case_has_active_jobs", lambda r, c: active)
    monkeypatch.setattr(ingest_task, "_run_library_rules", lambda r, c: None)
    monkeypatch.setattr(ingest_task, "_run_watchlist", lambda r, c: None)
    monkeypatch.setattr(ingest_task, "_trigger_finalize_chain", lambda c: None)


def test_chain_hop_extends_lock_and_keeps_token(monkeypatch):
    r = FakeRedis()
    r.set("fo:alert_run_lock:c1", "tok1")
    r.hset("case:c1", "auto_ioc_match", "0")
    monkeypatch.setattr(ingest_task, "get_redis", lambda: r)
    _patch_idle(monkeypatch, active=True)
    scheduled = []
    monkeypatch.setattr(
        ingest_task.maybe_run_detections,
        "apply_async",
        lambda *a, **kw: scheduled.append((a, kw)),
    )

    res = ingest_task.maybe_run_detections("c1", _attempts=0, _token="tok1")

    assert res["status"] == "deferred"
    assert r.get("fo:alert_run_lock:c1") == "tok1"  # still ours
    assert r.expires["fo:alert_run_lock:c1"] == ingest_task._DETECTION_LOCK_TTL
    assert scheduled[0][1]["kwargs"]["_token"] == "tok1"
    assert scheduled[0][1]["kwargs"]["_attempts"] == 1


def test_chain_hop_bows_out_when_superseded(monkeypatch):
    r = FakeRedis()
    r.set("fo:alert_run_lock:c1", "other-chain")
    monkeypatch.setattr(ingest_task, "get_redis", lambda: r)
    _patch_idle(monkeypatch, active=True)
    scheduled = []
    monkeypatch.setattr(
        ingest_task.maybe_run_detections,
        "apply_async",
        lambda *a, **kw: scheduled.append((a, kw)),
    )

    res = ingest_task.maybe_run_detections("c1", _attempts=3, _token="tok1")

    assert res["status"] == "superseded"
    assert not scheduled  # no parallel chain
    assert r.get("fo:alert_run_lock:c1") == "other-chain"  # not our lock to touch


def test_abandoned_chain_releases_its_lock(monkeypatch):
    r = FakeRedis()
    r.set("fo:alert_run_lock:c1", "tok1")
    monkeypatch.setattr(ingest_task, "get_redis", lambda: r)
    _patch_idle(monkeypatch, active=True)

    res = ingest_task.maybe_run_detections("c1", _attempts=60, _token="tok1")

    assert res["status"] == "abandoned"
    assert r.get("fo:alert_run_lock:c1") is None


def test_completed_run_releases_only_its_own_lock(monkeypatch):
    r = FakeRedis()
    r.set("fo:alert_run_lock:c1", "tok1")
    r.hset("case:c1", "auto_ioc_match", "0")
    monkeypatch.setattr(ingest_task, "get_redis", lambda: r)
    _patch_idle(monkeypatch, active=False)

    res = ingest_task.maybe_run_detections("c1", _token="tok1")
    assert res["status"] == "completed"
    assert r.get("fo:alert_run_lock:c1") is None

    # A stale chain finishing after being superseded must not delete the new
    # chain's lock.
    r.set("fo:alert_run_lock:c1", "new-chain")
    res = ingest_task.maybe_run_detections("c1", _token="tok1")
    assert res["status"] == "completed"
    assert r.get("fo:alert_run_lock:c1") == "new-chain"
