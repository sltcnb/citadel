"""Router-level tests for the alert cooldown wiring.

Drives the actual run handlers (case-rule check + single run, library
run-library + single run) directly with a fakeredis and a stubbed ES
transport — the full FastAPI app pulls native deps, so handlers are called
as functions (Depends defaults are bypassed), matching api/conftest.py's
approach of avoiding the app for unit tests.

Pins the contract the frontend relies on:
  * a re-run inside the cooldown returns fired=False + suppressed_only match;
  * the persisted run record carries suppressed_total;
  * triage ignores suppressed_only matches.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import redis_keys as rk  # noqa: E402
import services.sigma_settings as ss  # noqa: E402
from services import rule_eval  # noqa: E402

import routers.alert_rules as case_rules  # noqa: E402
import routers.global_alert_rules as gar  # noqa: E402

RULE = {"id": "r1", "name": "Test Rule", "query": "a:b", "threshold": 1}


@pytest.fixture
def r(monkeypatch):
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(case_rules, "_r", lambda: fake)
    monkeypatch.setattr(gar, "_redis", lambda: fake)
    monkeypatch.setattr(ss, "get_redis", lambda: fake)
    return fake


@pytest.fixture
def es(monkeypatch):
    """Queue of canned ES responses, in consumption order."""
    responses: list[dict] = []
    monkeypatch.setattr(
        rule_eval, "es_req",
        lambda method, path, body=None: responses.pop(0) if responses else {},
    )
    return responses


def _hits(total, fo_ids):
    return {"hits": {"total": {"value": total},
                     "hits": [{"_source": {"fo_id": f}} for f in fo_ids]}}


def test_check_rules_records_suppression_in_the_run(r, es):
    r.set(rk.case_alert_rules("case1"), json.dumps([RULE]))

    es.append(_hits(3, ["e1", "e2"]))
    run = case_rules.check_rules("case1", _acl={})
    assert len(run["matches"]) == 1
    assert run["suppressed_total"] == 0

    es.append(_hits(3, ["e1", "e2"]))
    run = case_rules.check_rules("case1", _acl={})
    assert run["matches"][0]["suppressed_only"] is True
    assert run["matches"][0]["match_count"] == 0
    assert run["suppressed_total"] == 1


def test_single_case_rule_run_reports_fired_false_when_suppressed(r, es):
    r.set(rk.case_alert_rules("case1"), json.dumps([RULE]))

    es.append(_hits(2, ["e1"]))
    first = case_rules.run_single_rule("case1", "r1", _acl={})
    assert first["fired"] is True

    es.append(_hits(2, ["e1"]))
    second = case_rules.run_single_rule("case1", "r1", _acl={})
    assert second["fired"] is False
    assert second["match"]["suppressed_only"] is True


def test_run_library_suppresses_and_persists(r, es):
    r.set(rk.GLOBAL_ALERT_RULES, json.dumps([RULE]))

    es.append(_hits(2, ["e1"]))
    out = gar.run_library_against_case("case1", rule_types=[], _acl={})
    assert out["matches"][0]["match_count"] == 2

    es.append(_hits(2, ["e1"]))
    out = gar.run_library_against_case("case1", rule_types=[], _acl={})
    assert out["matches"][0]["suppressed_only"] is True
    persisted = json.loads(r.get(rk.case_alert_run("case1")))
    assert persisted["suppressed_total"] == 1


def test_run_single_library_rule_fired_flag(r, es):
    r.set(rk.GLOBAL_ALERT_RULES, json.dumps([RULE]))

    es.append(_hits(2, ["e1"]))
    assert gar.run_single_rule_against_case("case1", "r1", _acl={})["fired"] is True

    es.append(_hits(2, ["e1"]))
    out = gar.run_single_rule_against_case("case1", "r1", _acl={})
    assert out["fired"] is False
    assert out["match"]["suppressed_only"] is True


def test_triage_skips_suppressed_only_matches(r, es, monkeypatch):
    r.set(rk.GLOBAL_ALERT_RULES, json.dumps([RULE]))

    es.append(_hits(2, ["e1"]))
    gar.run_library_against_case("case1", rule_types=[], _acl={})

    calls: list = []

    def fake_trigger(case_id, matches, limit=3):
        calls.append(matches)
        return [{"rule_id": m["rule"]["id"]} for m in matches]

    monkeypatch.setattr("services.alert_triage.trigger_triage", fake_trigger)

    out = gar.triage_alerts("case1", _acl={})
    assert len(out["triaged"]) == 1, "the firing match is triaged"

    # Re-run inside the cooldown: only a suppressed_only match remains.
    es.append(_hits(2, ["e1"]))
    gar.run_library_against_case("case1", rule_types=[], _acl={})
    out = gar.triage_alerts("case1", _acl={})
    assert out["triaged"] == []
    assert "No fired rules" in out["detail"]
