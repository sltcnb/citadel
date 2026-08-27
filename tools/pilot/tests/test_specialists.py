"""Specialist lenses: viability planning.

These pin the behaviour the module exists for. A real run on a case holding 45
syslog events and nothing else spent 40 of its 40 steps hunting for browser,
network and process artifacts that were never collected, and closed
"inconclusive — no determinative evidence" at 40% confidence. The correct
output was available before the first search and is a different claim: the
evidence needed to answer the question is not in the case.
"""

from __future__ import annotations

import sys
from pathlib import Path

# The pilot package lives one level up; match the sibling suite's convention
# rather than depending on an editable install being present.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pilot.specialists import (  # noqa: E402
    SPECIALISTS,
    SPECIALISTS_BY_ID,
    coverage_summary,
    plan,
    plan_block,
    specialist_prompt,
)

# The case from the trace: one macOS host, syslog only.
SYSLOG_ONLY = ["syslog"]
# The same host once the macOS parsers actually read what Talon collected.
MACOS_PARSED = [
    "syslog",
    "macos_triage",
    "process",
    "network_conn",
    "browser",
    "persistence",
    "macos_uls",
    "installed_software",
]


def test_syslog_only_case_is_not_answerable():
    p = plan(SYSLOG_ONLY)
    assert p.is_answerable is False
    # Only the always-on sequencing lens survives.
    assert [s.id for s in p.viable] == ["timeline"]
    assert {s.id for s, _ in p.blocked} == {
        "execution",
        "persistence",
        "network",
        "identity",
        "malware",
    }


def test_unanswerable_case_says_collection_gap_not_no_evidence():
    """The distinction the whole module turns on."""
    text = plan_block(plan(SYSLOG_ONLY))
    assert "COLLECTION GAP" in text
    assert "no domain lens is viable" in text
    assert "absence as evidence of absence" in text.lower()


def test_blocked_lens_names_what_would_unblock_it():
    """A gap is only actionable if it says what to collect."""
    p = plan(SYSLOG_ONLY)
    blocked = dict((s.id, missing) for s, missing in p.blocked)
    assert "browser" in blocked["network"]
    assert "prefetch" in blocked["execution"]
    assert "plist" in blocked["persistence"]
    # Rendered too, not just in the structure.
    assert "browser" in plan_block(p)


def test_macos_parsing_work_makes_the_same_host_answerable():
    """Regression tie-in: the parsers now emit these types for a macOS bundle,
    and that is what turns the lenses on."""
    p = plan(MACOS_PARSED)
    assert p.is_answerable is True
    assert not p.blocked
    assert {s.id for s in p.viable} == {s.id for s in SPECIALISTS}


def test_timeline_lens_is_never_blocked():
    """Anything with events can be sequenced; blocking it would leave a case
    with no lens at all and nothing to report."""
    for types in ([], ["syslog"], MACOS_PARSED):
        assert "timeline" in {s.id for s in plan(types).viable}


def test_empty_case_yields_only_timeline():
    p = plan([])
    assert [s.id for s in p.viable] == ["timeline"]
    assert p.is_answerable is False


def test_wanted_restricts_to_named_lenses():
    p = plan(MACOS_PARSED, wanted=["network", "persistence"])
    assert {s.id for s in p.viable} == {"network", "persistence"}


def test_unknown_wanted_id_falls_back_to_all_not_to_nothing():
    """A bad id in a request must not silently produce a run that does nothing."""
    p = plan(MACOS_PARSED, wanted=["not-a-lens"])
    assert len(p.viable) == len(SPECIALISTS)


def test_partial_coverage_case():
    """A Windows EVTX-only case: several lenses work, network does not."""
    p = plan(["evtx", "registry", "prefetch"])
    ids = {s.id for s in p.viable}
    assert {"execution", "persistence", "identity"} <= ids
    assert "network" not in ids
    assert p.is_answerable is True


def test_every_specialist_has_a_mandate_and_tools():
    for s in SPECIALISTS:
        assert s.mandate.strip(), s.id
        assert s.lens.strip(), s.id
        assert s.tools, s.id
        # Every lens must be able to record what it establishes, or its work
        # never reaches the report.
        assert "save_finding" in s.tools, s.id
        assert "search" in s.tools, s.id


def test_specialist_ids_are_unique():
    ids = [s.id for s in SPECIALISTS]
    assert len(ids) == len(set(ids))
    assert set(SPECIALISTS_BY_ID) == set(ids)


def test_specialist_prompt_states_the_mandate_and_stays_in_lane():
    p = plan(MACOS_PARSED)
    text = specialist_prompt(SPECIALISTS_BY_ID["persistence"], p)
    assert "persistence" in text.lower()
    assert "Mandate:" in text
    assert "T1547" in text  # its MITRE techniques are named
    assert "save_finding" in text  # told how to hand off out-of-lens findings


def test_clean_negative_is_requested_explicitly():
    """"checked and found nothing" must be reportable as a result, or every
    lens that finds nothing looks identical to one that never ran."""
    text = specialist_prompt(SPECIALISTS_BY_ID["network"], plan(MACOS_PARSED))
    assert "negative" in text.lower()


def test_coverage_summary_is_serialisable_and_complete():
    summary = coverage_summary(plan(SYSLOG_ONLY))
    assert summary["answerable"] is False
    assert summary["viable"] == ["timeline"]
    assert "network" in summary["blocked"]
    assert summary["artifact_types_present"] == ["syslog"]
