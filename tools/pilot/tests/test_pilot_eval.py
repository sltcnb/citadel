#!/usr/bin/env python3
"""Tests for the autopilot scorer (tools/pilot/eval/scoring.py).

A scorer that is wrong is worse than no scorer: it would justify prompt changes
that make the agent worse. So these tests are deliberately adversarial about the
ways a run can *look* good — an agent that surfaces hundreds of events, cites
invented evidence, loops on empty queries, or hedges its verdict must all score
badly, and each for its own reason.

Pure stdlib; no LLM, no Elasticsearch. Runs under pytest and standalone.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "eval"))

import scoring  # noqa: E402

CORPUS = {"ev-1", "ev-2", "ev-3", "ev-4", "ev-5"}

RUBRIC = {
    "id": "shadow_copy_deletion",
    "key_evidence": ["ev-3"],
    "incident_confirmed": "yes",
    "techniques": ["T1490"],
    "max_steps": 10,
}


def _run(steps, final, stopped="concluded"):
    return {"steps": steps, "final": final, "step_count": len(steps),
            "stopped_reason": stopped}


def _good_run():
    return _run(
        [{"step": 1, "action": "aggregate", "agg_field": "artifact_type", "result_count": 5},
         {"step": 2, "action": "search", "query": "process.command_line:*vssadmin*",
          "result_count": 1, "sample_ids": ["ev-3"]},
         {"step": 3, "action": "inspect", "fo_id": "ev-3", "result_count": 1}],
        {"action": "conclude", "incident_confirmed": "yes",
         "verdict": "Shadow copies deleted via vssadmin.",
         "evidence": ["ev-3 — vssadmin delete shadows /all /quiet"],
         "mitre_techniques": ["T1490"]},
    )


# ── the happy path ───────────────────────────────────────────────────────────


def test_a_correct_run_passes_every_gate():
    card = scoring.score(_good_run(), RUBRIC, CORPUS)
    assert card.passed, str(card)
    assert card.composite > 0.95
    for m in card.metrics:
        assert m.passed, f"{m.name} should pass: {m.detail}"


# ── finding the evidence ─────────────────────────────────────────────────────


def test_missing_the_planted_evidence_fails():
    run = _run(
        [{"step": 1, "action": "search", "query": "foo", "result_count": 2,
          "sample_ids": ["ev-1", "ev-2"]}],
        {"action": "conclude", "incident_confirmed": "no", "evidence": ["ev-1"],
         "mitre_techniques": []},
    )
    card = scoring.score(run, RUBRIC, CORPUS)
    assert not card.passed
    ev = card.get("evidence_recall")
    assert ev.value == 0.0 and not ev.passed
    assert "ev-3" in ev.detail, "the missed id must be named so a failure is actionable"


def test_surfacing_evidence_only_via_inspect_still_counts():
    run = _run(
        [{"step": 1, "action": "inspect", "fo_id": "ev-3", "result_count": 1}],
        {"action": "conclude", "incident_confirmed": "yes", "evidence": ["ev-3"],
         "mitre_techniques": ["T1490"]},
    )
    assert scoring.score(run, RUBRIC, CORPUS).get("evidence_recall").value == 1.0


def test_volume_is_not_quality():
    """Surfacing hundreds of events without the planted one must not score well —
    'the agent looked at a lot of things' is the failure mode this guards."""
    run = _run(
        [{"step": i, "action": "search", "query": f"q{i}", "result_count": 50,
          "sample_ids": [f"noise-{i}-{j}" for j in range(20)]} for i in range(1, 9)],
        {"action": "conclude", "incident_confirmed": "yes",
         "evidence": ["lots of activity"], "mitre_techniques": ["T1490"]},
    )
    card = scoring.score(run, RUBRIC, CORPUS)
    assert not card.passed
    assert card.get("evidence_recall").value == 0.0


def test_partial_recall_honours_min_key_evidence():
    rubric = dict(RUBRIC, key_evidence=["ev-3", "ev-4"], min_key_evidence=1)
    card = scoring.score(_good_run(), rubric, CORPUS)
    ev = card.get("evidence_recall")
    assert ev.value == 0.5 and ev.passed, "1 of 2 satisfies min_key_evidence=1"

    strict = dict(RUBRIC, key_evidence=["ev-3", "ev-4"])
    assert not scoring.score(_good_run(), strict, CORPUS).get("evidence_recall").passed


# ── not inventing evidence ───────────────────────────────────────────────────


def test_invented_citation_is_caught():
    run = _good_run()
    run["final"]["evidence"] = ["ev-3 — real", "ev-99 — fabricated"]
    card = scoring.score(run, RUBRIC, CORPUS)
    g = card.get("citation_grounding")
    assert g.value == 0.5 and not g.passed
    assert "ev-99" in g.detail
    assert not card.passed, "a verdict resting on invented evidence must not pass"


def test_hyphenated_fixture_ids_are_not_truncated():
    """Regression: the id pattern excluded internal hyphens, so `ev-shadow-1`
    truncated to `ev-shadow` — absent from the corpus — and a correctly-cited run
    was reported as citing INVENTED evidence. A false accusation is the worst
    possible failure for this metric."""
    corpus = {"ev-shadow-1"}
    rubric = dict(RUBRIC, key_evidence=["ev-shadow-1"])
    run = _run(
        [{"step": 1, "action": "search", "query": "q", "result_count": 1,
          "sample_ids": ["ev-shadow-1"]}],
        {"action": "conclude", "incident_confirmed": "yes",
         "evidence": ["ev-shadow-1 \u2014 vssadmin.exe delete shadows /all /quiet"],
         "mitre_techniques": ["T1490"]},
    )
    assert scoring.cited_ids(run) == {"ev-shadow-1"}
    card = scoring.score(run, rubric, corpus)
    assert card.get("citation_grounding").value == 1.0, card.get("citation_grounding").detail
    assert card.passed


def test_uuid_style_ids_are_extracted_from_prose():
    uid = "3f2b1a44-9c8d-4e7f-b012-556677889900"
    run = _good_run()
    run["final"]["evidence"] = [f"see {uid} for the command line"]
    card = scoring.score(run, RUBRIC, CORPUS | {uid})
    assert card.get("citation_grounding").value == 1.0


def test_grounding_is_skipped_when_the_corpus_is_unknown():
    """Better to skip a metric than to guess: without the corpus a real id and a
    fabricated one are indistinguishable."""
    card = scoring.score(_good_run(), RUBRIC, None)
    g = card.get("citation_grounding")
    assert g.passed and "skipped" in g.detail


def test_concluding_with_no_citations_fails_by_default():
    run = _good_run()
    run["final"]["evidence"] = []
    assert not scoring.score(run, RUBRIC, CORPUS).get("citation_grounding").passed
    relaxed = dict(RUBRIC, require_citations=False)
    assert scoring.score(run, relaxed, CORPUS).get("citation_grounding").passed


# ── the verdict ──────────────────────────────────────────────────────────────


def test_wrong_verdict_fails_even_with_perfect_evidence():
    """Finding the events and drawing the right conclusion are separate skills;
    a harness that blends them cannot say which one broke."""
    run = _good_run()
    run["final"]["incident_confirmed"] = "no"
    card = scoring.score(run, RUBRIC, CORPUS)
    assert card.get("evidence_recall").passed
    assert not card.get("verdict").passed
    assert not card.passed


def test_partial_is_scored_as_near_miss_but_still_fails():
    run = _good_run()
    run["final"]["incident_confirmed"] = "partial"
    v = scoring.score(run, RUBRIC, CORPUS).get("verdict")
    assert v.value == 0.5 and not v.passed


def test_missing_verdict_is_reported_readably():
    run = _good_run()
    run["final"].pop("incident_confirmed")
    assert "(none)" in scoring.score(run, RUBRIC, CORPUS).get("verdict").detail


def test_bad_rubric_verdict_is_rejected_loudly():
    try:
        scoring.score(_good_run(), dict(RUBRIC, incident_confirmed="probably"), CORPUS)
    except ValueError as exc:
        assert "incident_confirmed" in str(exc)
    else:
        raise AssertionError("an unusable rubric must raise, not silently pass")


# ── techniques ───────────────────────────────────────────────────────────────


def test_subtechnique_satisfies_the_parent():
    run = _good_run()
    run["final"]["mitre_techniques"] = ["T1059.001"]
    card = scoring.score(run, dict(RUBRIC, techniques=["T1059"]), CORPUS)
    assert card.get("technique_recall").value == 1.0


def test_parent_does_not_satisfy_a_specific_subtechnique():
    run = _good_run()
    run["final"]["mitre_techniques"] = ["T1059"]
    card = scoring.score(run, dict(RUBRIC, techniques=["T1059.001"]), CORPUS)
    assert card.get("technique_recall").value == 0.0


# ── termination and waste ────────────────────────────────────────────────────


def test_running_out_of_budget_is_a_failure_even_if_correct():
    """The analyst waited for a conclusion the agent never committed to."""
    run = _good_run()
    run["stopped_reason"] = "max_steps_reached"
    card = scoring.score(run, RUBRIC, CORPUS)
    assert not card.get("termination").passed
    assert not card.passed


def test_repeated_empty_queries_count_as_waste():
    steps = [
        {"step": 1, "action": "search", "query": "delete OR unlink", "result_count": 0},
        {"step": 2, "action": "search", "query": "delete OR unlink", "result_count": 0},
        {"step": 3, "action": "search", "query": "DELETE or Unlink", "result_count": 0},
        {"step": 4, "action": "search", "query": "process.command_line:*vssadmin*",
         "result_count": 1, "sample_ids": ["ev-3"]},
    ]
    run = _run(steps, _good_run()["final"])
    waste = scoring.wasted_steps(run)
    assert waste == [2, 3], f"repeat-empty steps should be 2 and 3, got {waste}"
    assert "wasted" in scoring.score(run, RUBRIC, CORPUS).get("efficiency").detail


def test_a_first_empty_query_is_not_waste():
    """Ruling something out is progress — only the repeat is waste."""
    run = _run([{"step": 1, "action": "search", "query": "x", "result_count": 0}],
               _good_run()["final"])
    assert scoring.wasted_steps(run) == []


def test_efficiency_never_gates_the_scenario():
    """A correct slow answer must beat a fast wrong one."""
    slow = _good_run()
    slow["step_count"] = 40
    card = scoring.score(slow, RUBRIC, CORPUS)
    assert not card.get("efficiency").passed
    assert card.passed, "over budget but correct must still pass"


def test_composite_orders_runs_sensibly():
    good = scoring.score(_good_run(), RUBRIC, CORPUS).composite
    wrong_verdict = _good_run()
    wrong_verdict["final"]["incident_confirmed"] = "no"
    invented = _good_run()
    invented["final"]["evidence"] = ["ev-99"]
    missed = _run([{"step": 1, "action": "search", "query": "q", "result_count": 0}],
                  {"action": "conclude", "incident_confirmed": "no", "evidence": [],
                   "mitre_techniques": []})
    a = scoring.score(wrong_verdict, RUBRIC, CORPUS).composite
    b = scoring.score(invented, RUBRIC, CORPUS).composite
    c = scoring.score(missed, RUBRIC, CORPUS).composite
    assert good > a and good > b and a > c and b > c, (good, a, b, c)


def test_score_many_aggregates():
    rep = scoring.score_many([
        (_good_run(), RUBRIC, CORPUS),
        (_run([], {"action": "conclude", "incident_confirmed": "no", "evidence": []}),
         RUBRIC, CORPUS),
    ])
    assert rep["scenarios"] == 2 and rep["passed"] == 1
    assert 0.0 < rep["mean_composite"] < 1.0


# ── standalone runner (scripts/run_tests.sh calls `python3 <file>`) ───────────
def _main() -> int:
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in fns:
        try:
            fn()
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {name}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"ERROR {name}: {type(exc).__name__}: {exc}")
    if failed:
        print(f"{len(fns) - failed}/{len(fns)} passed, {failed} failed")
        return 1
    print(f"{len(fns)}/{len(fns)} passed (autopilot scorer)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
