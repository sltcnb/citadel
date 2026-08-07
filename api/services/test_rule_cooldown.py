"""Tests for the alert cooldown (detection dedup) wrapper in services/rule_eval.py.

The ES transport is stubbed (same pattern as test_rule_eval.py) and Redis is
fakeredis. Cooldown semantics pinned here:

  * first fire records a marker and alerts;
  * an identical re-match inside the window is suppressed_only (no new alert)
    but counted via suppressed_count;
  * a NEW signature (different samples / different correlation group) fires
    normally, even inside the window;
  * after the window expires the same match fires again;
  * per-rule cooldown_minutes overrides the 60-minute default;
  * Redis failures fail OPEN — cooldown is best-effort, detection is not.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import services.rule_eval as rule_eval  # noqa: E402

RULE = {"id": "r1", "name": "Test Rule", "query": "a:b", "threshold": 1}


@pytest.fixture
def r():
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture
def captured(monkeypatch):
    responses: list[dict] = []

    def fake(method, path, body=None):
        return responses.pop(0) if responses else {}

    monkeypatch.setattr(rule_eval, "es_req", fake)
    return responses


def _hits(total, fo_ids):
    return {"hits": {"total": {"value": total},
                     "hits": [{"_source": {"fo_id": f}} for f in fo_ids]}}


def _grouped(keys):
    return {
        "aggregations": {"g": {"buckets": [
            {"key": k, "doc_count": 25, "n": {"value": 25}} for k in keys
        ]}},
        "hits": {"total": {"value": 0}, "hits": []},
    }


_CORR_RULE = {
    "id": "c1", "name": "Spray", "query": "a:b", "threshold": 1,
    "correlation": {"group_by": "network.src_ip", "distinct": "user.name",
                    "min_distinct": 20},
}


# ── threshold rules ───────────────────────────────────────────────────────────


def test_first_fire_alerts_and_records_a_marker(captured, r):
    captured.append(_hits(3, ["e1", "e2"]))
    match = rule_eval.evaluate_with_cooldown("case1", RULE, r)
    assert match is not None
    assert not match.get("suppressed_only")
    assert match["suppressed_count"] == 0
    assert match["cooldown_minutes"] == 60.0
    markers = [k for k in r.keys() if k.startswith("fo:alert_cooldown:case1:r1:")]
    assert len(markers) == 1


def test_identical_rematch_is_suppressed_within_the_window(captured, r):
    captured.append(_hits(3, ["e1", "e2"]))
    first = rule_eval.evaluate_with_cooldown("case1", RULE, r)
    assert first and not first.get("suppressed_only")

    captured.append(_hits(3, ["e1", "e2"]))
    second = rule_eval.evaluate_with_cooldown("case1", RULE, r)
    assert second is not None, "suppressed matches persist for the run record"
    assert second["suppressed_only"] is True
    assert second["match_count"] == 0
    assert second["sample_events"] == []
    assert second["suppressed_count"] == 1
    assert second["suppressed_entities"] == ["case"]


def test_new_samples_are_a_new_signature_and_fire(captured, r):
    captured.append(_hits(3, ["e1", "e2"]))
    rule_eval.evaluate_with_cooldown("case1", RULE, r)

    captured.append(_hits(4, ["e9", "e8", "e7"]))
    match = rule_eval.evaluate_with_cooldown("case1", RULE, r)
    assert match and not match.get("suppressed_only")
    assert match["match_count"] == 4
    assert match["suppressed_count"] == 0


def test_fires_again_after_the_cooldown_expires(captured, r):
    rule = {**RULE, "cooldown_minutes": 0.01}  # → 1s TTL floor
    captured.append(_hits(3, ["e1", "e2"]))
    rule_eval.evaluate_with_cooldown("case1", rule, r)

    captured.append(_hits(3, ["e1", "e2"]))
    assert rule_eval.evaluate_with_cooldown("case1", rule, r)["suppressed_only"] is True

    time.sleep(1.2)
    captured.append(_hits(3, ["e1", "e2"]))
    match = rule_eval.evaluate_with_cooldown("case1", rule, r)
    assert match and not match.get("suppressed_only")


def test_per_rule_cooldown_overrides_the_default(captured, r):
    rule = {**RULE, "cooldown_minutes": 120}
    captured.append(_hits(1, ["e1"]))
    rule_eval.evaluate_with_cooldown("case1", rule, r)
    marker = next(iter(r.keys("fo:alert_cooldown:*")))
    assert 7100 < r.ttl(marker) <= 7200


def test_default_cooldown_is_sixty_minutes(captured, r):
    captured.append(_hits(1, ["e1"]))
    rule_eval.evaluate_with_cooldown("case1", RULE, r)
    marker = next(iter(r.keys("fo:alert_cooldown:*")))
    assert 3500 < r.ttl(marker) <= 3600


def test_no_redis_means_no_cooldown(captured):
    captured.append(_hits(2, ["e1"]))
    match = rule_eval.evaluate_with_cooldown("case1", RULE, None)
    assert match and match["suppressed_count"] == 0


def test_redis_failure_fails_open(captured):
    class BrokenRedis:
        def pipeline(self, **kwargs):
            raise ConnectionError("redis down")

    captured.append(_hits(2, ["e1"]))
    match = rule_eval.evaluate_with_cooldown("case1", RULE, BrokenRedis())
    assert match is not None
    assert not match.get("suppressed_only")
    assert match["match_count"] == 2


# ── correlation rules ─────────────────────────────────────────────────────────


def test_correlation_same_entity_is_suppressed(captured, r):
    captured.extend([_grouped(["10.0.0.66"]), _hits(25, ["e1"])])
    first = rule_eval.evaluate_with_cooldown("case1", _CORR_RULE, r)
    assert first and not first.get("suppressed_only")

    captured.extend([_grouped(["10.0.0.66"]), _hits(25, ["e1"])])
    second = rule_eval.evaluate_with_cooldown("case1", _CORR_RULE, r)
    assert second["suppressed_only"] is True
    assert second["suppressed_count"] == 1
    assert second["suppressed_entities"] == ["10.0.0.66"]


def test_correlation_new_entity_fires_and_match_is_narrowed(captured, r):
    captured.extend([_grouped(["10.0.0.66"]), _hits(25, ["e1"])])
    rule_eval.evaluate_with_cooldown("case1", _CORR_RULE, r)

    captured.extend([_grouped(["10.0.0.66", "10.0.0.99"]), _hits(50, ["e1", "e2"])])
    match = rule_eval.evaluate_with_cooldown("case1", _CORR_RULE, r)
    assert match and not match.get("suppressed_only")
    # Only the genuinely new entity fires; the known one is counted suppressed.
    assert match["match_count"] == 1
    assert [g["key"] for g in match["correlation"]["groups"]] == ["10.0.0.99"]
    assert "10.0.0.99" in match["correlation"]["summary"]
    assert match["suppressed_count"] == 1
    assert match["suppressed_entities"] == ["10.0.0.66"]


def test_suppressed_hit_does_not_extend_the_window(captured, r):
    """Fixed window: a persistent condition re-alerts once per cooldown."""
    rule = {**RULE, "cooldown_minutes": 0.01}
    captured.append(_hits(1, ["e1"]))
    rule_eval.evaluate_with_cooldown("case1", rule, r)
    marker = next(iter(r.keys("fo:alert_cooldown:*")))
    ttl_before = r.ttl(marker)

    captured.append(_hits(1, ["e1"]))
    rule_eval.evaluate_with_cooldown("case1", rule, r)
    assert r.ttl(marker) <= ttl_before, "suppressed hits must not refresh the TTL"
