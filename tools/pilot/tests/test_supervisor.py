"""Run control: direction, hypothesis lifecycle, stopping.

The agent used to decide all three for itself, which is how a run spent 40
steps hunting artifacts that were never collected and then self-certified
"inconclusive" at 40% confidence. The existing guards are loop detectors, and
they cannot catch that case: varied, well-formed, non-repeating queries against
evidence that does not exist never repeat, so nothing trips.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pilot.supervisor import (  # noqa: E402
    CONCLUDE,
    CONTINUE,
    NEEDS_JUDGMENT,
    REDIRECT,
    assess,
    measure,
    summarise,
)


def _step(action="search", ok=True, ids=None, count=None, **kw):
    s = {
        "action": action,
        "query_status": "ok" if ok else "invalid",
        "sample_ids": ids or [],
    }
    if count is not None:
        s["result_count"] = count
    s.update(kw)
    return s


# ── measure ───────────────────────────────────────────────────────────────────


def test_progress_is_new_evidence_not_activity():
    """Thirty queries returning the same population is not thirty steps of
    progress — it is one, and then twenty-nine of motion."""
    t = [_step(ids=["a", "b"], count=2)] + [_step(ids=["a", "b"], count=2) for _ in range(9)]
    p = measure(t)
    assert p.steps == 10
    assert len(p.productive_steps) == 1
    assert p.idle_steps == 9


def test_zero_hit_and_rejected_steps_are_never_progress():
    t = [_step(ids=[], count=0), _step(ok=False), _step(ids=[], count=0)]
    p = measure(t)
    assert p.productive_steps == []
    assert p.idle_steps == 3


def test_a_tool_without_event_ids_can_still_establish_something():
    """ioc_sweep and host_profile return findings, not fo_ids; ignoring them
    would make a productive run look idle."""
    p = measure([_step(action="ioc_sweep", ids=[], count=3)])
    assert len(p.productive_steps) == 1


def test_lens_coverage_is_inferred_from_the_queries():
    t = [
        _step(query="artifact_type:network_conn AND network.dst_ip:1.2.3.4"),
        _step(query="artifact_type:persistence"),
    ]
    assert measure(t).lenses_touched == {"network", "persistence"}


# ── The failure this exists for ───────────────────────────────────────────────


def test_unanswerable_case_is_stopped_instead_of_searched():
    """The trace: no domain lens viable, 40 steps spent anyway."""
    t = [_step(ids=[], count=0) for _ in range(6)]
    d = assess(t, step_no=6, max_steps=40, plan_answerable=False, viable_lenses=["timeline"])
    assert d.action == CONCLUDE
    assert "cannot be settled" in d.reason
    assert "collection gap" in d.guidance


def test_unanswerable_case_still_gets_a_few_steps_to_establish_what_is_present():
    """Stopping at step 1 would report a gap without characterising the data."""
    d = assess([], step_no=2, max_steps=40, plan_answerable=False)
    assert d.action == CONTINUE


def test_conclusion_guidance_forbids_reading_absence_as_innocence():
    d = assess(
        [_step(ids=[], count=0) for _ in range(6)],
        step_no=6,
        max_steps=40,
        plan_answerable=False,
    )
    assert "evidence that nothing happened" in d.guidance


# ── Stall handling ────────────────────────────────────────────────────────────


def test_stalled_run_is_redirected_to_a_lens_never_probed():
    """The productive move when a line dies is a different lens, not more of
    the same line."""
    t = [_step(query="artifact_type:network_conn", ids=[], count=0) for _ in range(8)]
    d = assess(
        t, step_no=8, max_steps=40, viable_lenses=["network", "persistence", "execution"]
    )
    assert d.action == REDIRECT
    assert d.target in {"persistence", "execution"}
    assert "never probed" in d.reason


def test_stalled_run_with_every_lens_probed_escalates_to_judgment():
    """Nothing deterministic left to decide — hand it to the adjudicator rather
    than guess."""
    t = [
        _step(query="artifact_type:network_conn", ids=[], count=0),
        _step(query="artifact_type:persistence", ids=[], count=0),
    ] + [_step(ids=[], count=0) for _ in range(6)]
    d = assess(t, step_no=8, max_steps=40, viable_lenses=["network", "persistence"])
    assert d.action == NEEDS_JUDGMENT
    assert "do not keep searching" in d.guidance.lower()


def test_a_productive_run_is_left_alone():
    t = [_step(ids=[f"e{i}"], count=1) for i in range(8)]
    d = assess(t, step_no=8, max_steps=40, viable_lenses=["network"])
    assert d.action == CONTINUE


def test_varied_queries_against_absent_evidence_are_caught():
    """Precisely what the loop detectors miss: every query different, every
    result empty, nothing ever repeats."""
    t = [_step(query=f"artifact_type:browser AND message:*term{i}*", ids=[], count=0) for i in range(7)]
    d = assess(t, step_no=7, max_steps=40, viable_lenses=["network", "execution"])
    assert d.action != CONTINUE


# ── Budget ────────────────────────────────────────────────────────────────────


def test_budget_exhaustion_concludes():
    d = assess([_step(ids=["a"])], step_no=40, max_steps=40)
    assert d.action == CONCLUDE
    assert "budget exhausted" in d.reason


def test_stops_before_the_cap_so_the_conclusion_is_written_deliberately():
    """Hitting the ceiling mid-thought truncates the verdict."""
    t = [_step(ids=[f"e{i}"], count=1) for i in range(30)] + [
        _step(ids=[], count=0) for _ in range(3)
    ]
    d = assess(t, step_no=33, max_steps=40, viable_lenses=["network"])
    assert d.action == CONCLUDE
    assert "no new evidence" in d.reason


def test_early_steps_are_not_stopped_for_idleness():
    """A run has to be allowed to orient before anything counts as stalling."""
    d = assess([_step(ids=[], count=0) for _ in range(3)], step_no=3, max_steps=40)
    assert d.action == CONTINUE


# ── Directive plumbing ────────────────────────────────────────────────────────


def test_continue_injects_nothing_into_the_prompt():
    assert assess([], step_no=1, max_steps=40).as_prompt() == ""


def test_non_continue_directives_are_labelled_for_the_agent():
    d = assess(
        [_step(ids=[], count=0) for _ in range(6)],
        step_no=6,
        max_steps=40,
        plan_answerable=False,
    )
    text = d.as_prompt()
    assert "SUPERVISOR" in text
    assert d.reason in text
    assert d.is_terminal is True


def test_summarise_is_serialisable_control_state():
    t = [_step(ids=["a"], count=1), _step(ids=[], count=0)]
    s = summarise(t, assess(t, step_no=2, max_steps=40))
    assert s["steps"] == 2
    assert s["productive_steps"] == 1
    assert s["idle_steps"] == 1
    assert s["directive"] == CONTINUE
