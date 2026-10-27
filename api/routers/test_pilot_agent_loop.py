"""Agent loop vs. unusable LLM replies.

GLM once answered a step with a bare fragment ({"hypotheses": [...]}, no
"action"). The loop defaulted a missing action to "conclude", so the run ended
at step 7 of 200 with an empty verdict, labelled "step cap reached".
"""
import sys
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_CONCLUDE = (
    '{"action":"conclude","verdict":"benign","incident_confirmed":"no",'
    '"evidence":["e1"],"indicators":[],"confidence":70,'
    '"confidence_rationale":"e1 settles it"}'
)


@pytest.fixture
def run_agent(monkeypatch):
    fake = fakeredis.FakeRedis(decode_responses=True)
    import config
    import services.cases as cases
    from pilot import service

    monkeypatch.setattr(config, "get_redis", lambda: fake)
    monkeypatch.setattr(cases, "get_redis", lambda: fake)
    monkeypatch.setattr(cases, "get_case", lambda cid: {"case_id": cid, "name": "t"})
    monkeypatch.setattr(service, "_redis", lambda: fake)

    def run(step_replies):
        replies = iter(step_replies)

        def fake_llm(cfg, system, user, max_tokens=600, json_mode=False):
            # Only the investigation agent consumes the script; the reviewer
            # and report passes get a harmless object.
            if system.startswith("You are an autonomous DFIR investigation agent"):
                return next(replies, _CONCLUDE)
            return '{"ok": true}'

        monkeypatch.setattr(service, "_call_llm_with_system", fake_llm)
        events = list(service._agent_run("c1", "test", 10, {"provider": "openai"}, None))
        return next(e["run"] for e in events if e.get("type") == "done")

    return run


def test_reply_without_action_does_not_end_the_run(run_agent):
    run = run_agent(['{"hypotheses": []}', '{"hypotheses": []}', _CONCLUDE])
    actions = [s.get("action") for s in run["steps"]]
    assert actions == ["error", "conclude"]
    assert run["final"]["verdict"] == "benign"
    assert run["stopped_reason"] == "concluded"


def test_corrective_reask_recovers_within_the_same_step(run_agent):
    run = run_agent(["not json at all", _CONCLUDE])
    assert [s.get("action") for s in run["steps"]] == ["conclude"]
    assert run["stopped_reason"] == "concluded"


def test_persistent_garbage_stops_with_an_honest_reason(run_agent):
    run = run_agent(["{}"] * 20)
    assert run["stopped_reason"] == "llm_error"
    assert "unusable replies in a row" in run["final"]["verdict"]
    assert [s.get("action") for s in run["steps"]][:3] == ["error"] * 3


def test_conclusion_is_sent_back_while_an_alert_anchor_is_untested(monkeypatch):
    """The SMB-drop run never searched the alert's source port."""
    fake = fakeredis.FakeRedis(decode_responses=True)
    import config
    import services.cases as cases
    from pilot import service

    monkeypatch.setattr(config, "get_redis", lambda: fake)
    monkeypatch.setattr(cases, "get_redis", lambda: fake)
    monkeypatch.setattr(cases, "get_case", lambda cid: {"case_id": cid, "name": "t"})
    monkeypatch.setattr(service, "_redis", lambda: fake)
    replies = iter([
        _CONCLUDE,                                                     # too early
        '{"action":"session_pivot","thought":"t","port":64721}',
        _CONCLUDE,                                                     # now accepted
    ])
    seen_prompts = []

    def fake_llm(cfg, system, user, max_tokens=600, json_mode=False):
        if system.startswith("You are an autonomous DFIR investigation agent"):
            seen_prompts.append(user)
            return next(replies, _CONCLUDE)
        return '{"holds": true, "issues": []}'

    monkeypatch.setattr(service, "_call_llm_with_system", fake_llm)
    monkeypatch.setitem(service.AGENT_TOOLS, "session_pivot", lambda cid, step: {
        "query_status": "ok", "result_count": 1, "logons": [{"fo_id": "e1"}], "summary": ["JOIN → e1"]})
    events = list(service._agent_run("c1", "Source port : 64721", 10, {"provider": "openai"}, None))
    run = next(e["run"] for e in events if e.get("type") == "done")
    assert [s.get("action") for s in run["steps"]] == ["review", "session_pivot", "conclude"]
    assert "untested anchor port 64721" in run["steps"][0]["thought"]
    assert "REVIEW — your conclusion was NOT accepted" in seen_prompts[1]
    assert run["stopped_reason"] == "concluded"


def test_reviewer_rejection_sends_the_conclusion_back_once_then_accepts(run_agent, monkeypatch):
    from pilot import service

    verdicts = iter([
        '{"holds": false, "issues": ["H2 marked refuted from absence of evidence"], "adjusted_confidence": 40}',
        '{"holds": true, "issues": [], "adjusted_confidence": 55}',
    ])
    def fake_verify(cfg, intro, step, transcript=None):
        import json as _j
        return _j.loads(next(verdicts))

    monkeypatch.setattr(service, "_verify_conclusion", fake_verify)
    run = run_agent([_CONCLUDE, _CONCLUDE])
    assert [s.get("action") for s in run["steps"]] == ["review", "conclude"]
    assert "refuted from absence" in run["steps"][0]["thought"]
    assert run["final"]["confidence"] == 55
