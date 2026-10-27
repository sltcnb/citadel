"""Conclusion schema v2 — every rule, accept and reject."""
import copy

from pilot.anchors import Anchor
from pilot.conclusion import Context, alert_time, finalize, join_confirmed, parse_prior_confidence, validate

ANCHORS = [Anchor("port", "51021"), Anchor("ip", "10.0.0.5"), Anchor("account", "app_x")]
PIVOT = {"step": 3, "action": "session_pivot", "result_count": 1,
         "logons": [{"fo_id": "ev-001", "TargetUserName": "svc_b"}],
         "sessions": [{"events": [{"fo_id": "ev-002"}]}]}
COVERAGE = {"step": 4, "action": "coverage_check", "result_count": 10}
DET = {"id": "det-1", "title": "NTLM logon", "timestamp": "2026-10-21T08:03:00Z"}

GOOD = {
    "incident_confirmed": "no",
    "verdict": "the svc_b session (ev-001) wrote the file",
    "confidence": 72, "prior_confidence": 60,
    "confidence_rationale": "port join ev-001 attributes the write to svc_b",
    "entities": [
        {"kind": "ip", "value": "10.0.0.5", "status": "confirmed", "fo_ids": ["ev-001"]},
        {"kind": "account", "value": "app_x", "status": "contradicted", "fo_ids": ["ev-001"]},
    ],
    "discrepancies": [{"field": "account", "alert_value": "app_x", "evidence_value": "svc_b",
                       "fo_ids": ["ev-001"], "resolved": False}],
    "claims": [{"text": "logon on port 51021 is svc_b", "provenance": "collected", "fo_ids": ["ev-001"]},
               {"text": "no recurrence over 7 days", "provenance": "analyst"}],
    "case_context": [{"id": "det-1", "status": "related", "reason": "same session"}],
    "hypotheses": [{"id": "H2", "claim": "malicious use", "status": "unsupported", "against_evidence": []}],
    "next_actions": [{"owner": "backup team", "question": "job at 08:03?", "addresses": "account discrepancy"}],
    "indicators": [r"C:\Windows\testX.tmp"],
}


def ctx(transcript=None, prior=60, dets=(DET,)):
    return Context(anchors=ANCHORS, transcript=transcript if transcript is not None else [PIVOT, COVERAGE],
                   prior_confidence=prior, case_detections=list(dets))


def bad(**changes):
    c = copy.deepcopy(GOOD)
    for k, v in changes.items():
        if v is None:
            c.pop(k, None)
        else:
            c[k] = v
    return c


def test_a_complete_conclusion_passes():
    assert validate(GOOD, ctx()) == []


def test_join_key_must_be_used():
    issues = validate(GOOD, ctx(transcript=[COVERAGE]))
    assert any("join key (port 51021)" in i for i in issues)
    assert any('verdict "no" needs' in i for i in issues)


def test_every_alert_entity_needs_a_status():
    c = bad(entities=[GOOD["entities"][0]])
    assert any('no status for alert account "app_x"' in i for i in validate(c, ctx()))


def test_confirmed_entity_must_cite_a_seen_fo_id():
    c = bad(entities=[{"kind": "ip", "value": "10.0.0.5", "status": "confirmed", "fo_ids": ["made-up"]},
                      GOOD["entities"][1]])
    assert any('"10.0.0.5" is confirmed but cites no fo_id' in i for i in validate(c, ctx()))


def test_contradicted_entity_needs_a_discrepancy():
    assert any("not listed in discrepancies" in i for i in validate(bad(discrepancies=[]), ctx()))


def test_collected_claim_needs_fo_ids_but_analyst_claim_does_not():
    c = bad(claims=[{"text": "x", "provenance": "collected"}, {"text": "y", "provenance": "analyst"}])
    issues = validate(c, ctx())
    assert any("claims[0]" in i and "marked collected" in i for i in issues)
    assert not any("claims[1]" in i for i in issues)


def test_confidence_must_move_from_the_prior_when_unknowns_are_resolved():
    assert any("keep exactly the prior" in i for i in validate(bad(confidence=60), ctx()))
    assert any("state it" in i for i in validate(bad(prior_confidence=None), ctx()))
    assert any("confidence_rationale" in i for i in validate(bad(confidence_rationale=""), ctx()))
    # inconclusive and no refutation: keeping the prior is allowed
    assert not any("keep exactly" in i for i in validate(bad(confidence=60, incident_confirmed="inconclusive"), ctx()))


def test_prior_detections_must_be_addressed():
    assert any("det-1" in i for i in validate(bad(case_context=[]), ctx()))
    c = bad(case_context=[{"id": "det-1", "status": "unrelated"}])
    assert any("without a reason" in i for i in validate(c, ctx()))


def test_routine_needs_numbers_and_numbers_must_agree():
    routine = bad(verdict="routine backup activity (ev-001)")
    assert any("add baseline entries" in i for i in validate(routine, ctx()))
    spiky = bad(verdict="routine backup activity", baseline=[{"metric": "logons", "alert_value": 24, "baseline_value": 4}])
    assert any("6.0× its baseline" in i for i in validate(spiky, ctx()))
    calm = bad(verdict="routine backup activity", baseline=[{"metric": "logons", "alert_value": 4, "baseline_value": 4}])
    assert not any("baseline" in i for i in validate(calm, ctx()))


def test_absence_claims_need_a_coverage_check():
    c = bad(verdict="no execution was found after the drop")
    assert any("coverage_check" in i for i in validate(c, ctx(transcript=[PIVOT])))
    assert not any("absence" in i for i in validate(c, ctx()))


def test_generalisation_needs_an_aggregate():
    c = bad(verdict="all six events came from the EDR")
    assert any("generalisation" in i for i in validate(c, ctx()))
    agg = {"step": 5, "action": "aggregate", "result_count": 6}
    assert not any("generalisation" in i for i in validate(c, ctx(transcript=[PIVOT, COVERAGE, agg])))


def test_next_actions_must_be_executable_and_tied_to_a_question():
    c = bad(next_actions=[{"question": "look again"}])
    issues = validate(c, ctx())
    assert any("tool+params or owner+question" in i for i in issues)
    assert any("addresses" in i for i in issues)


def test_refuted_by_legitimacy_is_downgraded():
    c = bad(hypotheses=[{"id": "H2", "claim": "malicious", "status": "refuted",
                         "against_evidence": ["source is the legitimate backup server (ev-001)"]}])
    out = finalize(c, ctx())
    assert out["hypotheses"][0]["status"] == "unsupported"
    assert "legitimacy is not a refutation" in out["validation"]["adjustments"][0]


def test_refuted_with_a_contradicting_fo_id_stands():
    c = bad(hypotheses=[{"id": "H3", "claim": "file never written", "status": "refuted",
                         "against_evidence": ["session ev-002 shows the write"]}])
    assert finalize(c, ctx())["hypotheses"][0]["status"] == "refuted"


def test_verdict_without_a_join_is_gated_to_inconclusive():
    out = finalize(GOOD, ctx(transcript=[COVERAGE]))
    assert out["incident_confirmed"] == "inconclusive"
    assert out["leading_explanation"] == GOOD["verdict"]


def test_finalize_surfaces_discrepancies_derives_v1_fields_and_cleans_iocs():
    c = bad(evidence=None, next_steps=None, indicators=["C:Windows\testX.tmp", r"C:\Windows\testX.tmp"])
    out = finalize(c, ctx())
    assert out["schema_version"] == 2
    assert any("alert says app_x, evidence shows svc_b" in q for q in out["open_questions"])
    assert out["evidence"][0].startswith("[collected] logon on port 51021")
    assert out["next_steps"] == ["Ask backup team: job at 08:03? — resolves: account discrepancy"]
    assert out["indicators"] == [r"C:\Windows\testX.tmp"] and out["ioc_warnings"]
    assert all(out["checklist"].values())


def test_join_confirmed_by_a_search_on_the_port():
    s = {"step": 2, "action": "search", "query": "network.src_port:51021", "result_count": 1}
    assert join_confirmed(ctx(transcript=[s]))
    assert not join_confirmed(ctx(transcript=[{**s, "result_count": 0}]))


def test_prior_confidence_and_alert_time_parsing():
    assert parse_prior_confidence("Notre analyse conclut : indéterminé (confiance 60 %).") == 60
    assert parse_prior_confidence("benign at 70 % confidence") == 70
    assert parse_prior_confidence("no figure") is None
    assert alert_time("Heure : 21 Oct 2026 10:04:14").isoformat().startswith("2026-10-21T10:04:14")
    assert alert_time("at 2026-10-05 02:05:40 UTC").hour == 2
    assert alert_time("le 21/10/2026 10:04").month == 10
