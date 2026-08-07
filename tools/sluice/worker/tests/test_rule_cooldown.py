"""Tests for the worker-side cooldown (detection dedup) port and its wiring
into the ingest auto-run.

Mirrors api/services/test_rule_cooldown.py — the worker rule_eval is a port of
the API reference and must behave identically — plus an integration test over
tasks/ingest_task._run_library_rules proving suppressed matches produce no
detection event and no webhook while still landing in the run record.
"""

from __future__ import annotations

import hashlib
import json
import time

import fakeredis
import pytest
import redis_keys as rk
import rule_eval
from tasks import ingest_task

RULE = {"id": "r1", "name": "Test Rule", "query": "a:b", "threshold": 1}


@pytest.fixture
def r():
    return fakeredis.FakeRedis(decode_responses=True)


def _hits(total, fo_ids):
    return {"hits": {"total": {"value": total},
                     "hits": [{"_source": {"fo_id": f}} for f in fo_ids]}}


def _search_with(responses):
    """Injectable search behaving like rule_eval._search (None = no match)."""
    def search(index, body):
        return responses.pop(0) if responses else None
    return search


# ── wrapper behaviour (port parity) ──────────────────────────────────────────


def test_first_fire_alerts_and_records_a_marker(r):
    match = rule_eval.evaluate_with_cooldown(
        "case1", RULE, r, search=_search_with([_hits(3, ["e1", "e2"])]))
    assert match is not None
    assert not match.get("suppressed_only")
    assert match["suppressed_count"] == 0
    assert len(r.keys("fo:alert_cooldown:case1:r1:*")) == 1


def test_identical_rematch_is_suppressed_within_the_window(r):
    rule_eval.evaluate_with_cooldown(
        "case1", RULE, r, search=_search_with([_hits(3, ["e1", "e2"])]))
    second = rule_eval.evaluate_with_cooldown(
        "case1", RULE, r, search=_search_with([_hits(3, ["e1", "e2"])]))
    assert second["suppressed_only"] is True
    assert second["match_count"] == 0
    assert second["suppressed_count"] == 1


def test_new_samples_are_a_new_signature_and_fire(r):
    rule_eval.evaluate_with_cooldown(
        "case1", RULE, r, search=_search_with([_hits(3, ["e1", "e2"])]))
    match = rule_eval.evaluate_with_cooldown(
        "case1", RULE, r, search=_search_with([_hits(4, ["e9"])]))
    assert match and not match.get("suppressed_only")
    assert match["match_count"] == 4


def test_fires_again_after_the_cooldown_expires(r):
    rule = {**RULE, "cooldown_minutes": 0.01}  # → 1s TTL floor
    rule_eval.evaluate_with_cooldown(
        "case1", rule, r, search=_search_with([_hits(1, ["e1"])]))
    suppressed = rule_eval.evaluate_with_cooldown(
        "case1", rule, r, search=_search_with([_hits(1, ["e1"])]))
    assert suppressed["suppressed_only"] is True
    time.sleep(1.2)
    again = rule_eval.evaluate_with_cooldown(
        "case1", rule, r, search=_search_with([_hits(1, ["e1"])]))
    assert again and not again.get("suppressed_only")


def test_redis_failure_fails_open():
    class BrokenRedis:
        def pipeline(self, **kwargs):
            raise ConnectionError("redis down")

    match = rule_eval.evaluate_with_cooldown(
        "case1", RULE, BrokenRedis(), search=_search_with([_hits(2, ["e1"])]))
    assert match is not None and not match.get("suppressed_only")


def test_correlation_new_entity_fires_and_match_is_narrowed(r):
    corr_rule = {
        "id": "c1", "name": "Spray", "query": "a:b", "threshold": 1,
        "correlation": {"group_by": "network.src_ip", "distinct": "user.name",
                        "min_distinct": 20},
    }

    def grouped(keys):
        return {"aggregations": {"g": {"buckets": [
            {"key": k, "doc_count": 25, "n": {"value": 25}} for k in keys
        ]}}, "hits": {"total": {"value": 0}, "hits": []}}

    rule_eval.evaluate_with_cooldown(
        "case1", corr_rule, r,
        search=_search_with([grouped(["10.0.0.66"]), _hits(25, ["e1"])]))
    match = rule_eval.evaluate_with_cooldown(
        "case1", corr_rule, r,
        search=_search_with([grouped(["10.0.0.66", "10.0.0.99"]), _hits(50, ["e1"])]))
    assert match and not match.get("suppressed_only")
    assert match["match_count"] == 1
    assert [g["key"] for g in match["correlation"]["groups"]] == ["10.0.0.99"]
    assert match["suppressed_count"] == 1


def test_marker_key_format_matches_the_api_side():
    """Both deployables read/write the same markers — the format is a contract."""
    digest = hashlib.sha256(b"10.0.0.66").hexdigest()[:24]
    assert rule_eval.cooldown_key("case1", "r1", "10.0.0.66") == (
        f"fo:alert_cooldown:case1:r1:{digest}"
    )


# ── auto-run integration: suppressed matches don't alert ─────────────────────


def test_auto_run_dedups_detection_events_and_webhooks(monkeypatch, r):
    import tasks._webhooks as webhooks

    r.set(rk.GLOBAL_ALERT_RULES, json.dumps([RULE]))

    indexed: list[dict] = []

    class FakeIndexer:
        def __init__(self, url):
            pass

        def bulk_index(self, case_id, events):
            indexed.extend(events)

    fired: list = []
    monkeypatch.setattr(ingest_task, "ESBulkIndexer", FakeIndexer)
    monkeypatch.setattr(webhooks, "fire_webhooks", lambda *a, **k: fired.append(a))
    monkeypatch.setattr(
        rule_eval, "_search",
        _search_with([_hits(3, ["e1", "e2"]),  # run 1: fires
                      _hits(3, ["e1", "e2"]),  # run 2: identical → suppressed
                      _hits(4, ["e9"])]),      # run 3: new samples → fires
    )

    ingest_task._run_library_rules(r, "case1")
    assert len(indexed) == 1, "first run indexes one detection event"
    assert len(fired) == 1, "first run fires the webhook"
    run = json.loads(r.get(rk.case_alert_run("case1")))
    assert run["suppressed_total"] == 0

    ingest_task._run_library_rules(r, "case1")
    assert len(indexed) == 1, "suppressed re-match must not index a new detection"
    assert len(fired) == 1, "suppressed re-match must not fire the webhook"
    run = json.loads(r.get(rk.case_alert_run("case1")))
    assert run["suppressed_total"] == 1
    assert run["matches"][0]["suppressed_only"] is True
    assert run["matches"][0]["suppressed_count"] == 1

    ingest_task._run_library_rules(r, "case1")
    assert len(indexed) == 2, "new evidence fires normally inside the window"
    assert len(fired) == 2
