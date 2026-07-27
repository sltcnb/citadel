"""Pilot search strategy — funnel narrowing, progressive broadening, field coverage.

The behaviour under test is what stops the agent drawing a confident wrong
conclusion. Two failure modes, both silent:

  1. **Over-narrow first query.** The agent opens with its most specific guess,
     gets 0 hits, and reads that as "did not happen". Recovering needs a walk
     back UP the funnel, not one broadening step.

  2. **Structural blindness.** Artifact types populate different fields, so
     ANDing a sparse field discards every type that does not fill it. The result
     is a plausible hit count computed over a fraction of the evidence — which
     reads as an answer. `process.command_line` is Sysmon-only; MFT records have
     no user; syslog has no `evtx.*`. "0 hits on that field" and "did not happen"
     are different claims and support opposite conclusions.

Runnable standalone (python3 tools/pilot/tests/test_query_strategy.py) to match
the dependency-light suite convention in scripts/run_tests.sh — service.py
imports FastAPI/Redis/ES and cannot load in that gate, which is exactly why this
logic lives in a pure module.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pilot"))

from query_strategy import (  # noqa: E402
    SPARSE_FRACTION,
    USABLE_HIT_CEILING,
    auto_broaden,
    broaden_ladder,
    coverage_warning,
    query_fields,
)


def _raises(exc, fn):
    try:
        fn()
    except exc:
        return
    raise AssertionError(f"expected {exc.__name__}")


# ── query_fields ──────────────────────────────────────────────────────────────


def test_extracts_dotted_and_bare_fields_in_order():
    assert query_fields("host.hostname:WIN01 AND process.command_line:*psexec*") == [
        "host.hostname",
        "process.command_line",
    ]


def test_ignores_colons_inside_quoted_values():
    """A URL in a quoted phrase must not register its scheme as a field."""
    got = query_fields('message:"GET http://evil.example/x" AND artifact_type:access_log')
    assert got == ["message", "artifact_type"], got
    assert "http" not in got


def test_ignores_lucene_operators():
    got = query_fields("evtx.event_id:4624 AND NOT host.hostname:DC01 OR user.name:jdoe")
    assert got == ["evtx.event_id", "host.hostname", "user.name"], got
    for op in ("and", "not", "or", "AND", "NOT", "OR"):
        assert op not in got


def test_range_keyword_is_not_a_field():
    assert query_fields("network.dest_ip:10.0.0.9 TO 10.0.0.20") == ["network.dest_ip"]


def test_deduplicates_repeated_fields():
    assert query_fields("host.hostname:A OR host.hostname:B") == ["host.hostname"]


def test_no_fields_on_bare_wildcard():
    assert query_fields("*") == []
    assert query_fields("") == []
    assert query_fields(None) == []


def test_accepts_multiple_queries():
    assert query_fields("host.hostname:A", "user.name:B") == ["host.hostname", "user.name"]


# ── auto_broaden ──────────────────────────────────────────────────────────────


def test_drops_the_last_and_clause():
    assert auto_broaden("a:1 AND b:2 AND c:3") == "a:1 AND b:2"


def test_exact_match_becomes_wildcard_when_single_clause():
    assert auto_broaden('process.name:"psexec.exe"') == "process.name:*psexec.exe*"


def test_already_broad_returns_none():
    assert auto_broaden("artifact_type:evtx") is None
    assert auto_broaden("") is None


def test_and_inside_quotes_is_not_a_clause_boundary():
    """Splitting on a quoted ' AND ' would corrupt the query."""
    q = 'message:"cmd AND control" AND host.hostname:X'
    assert auto_broaden(q) == 'message:"cmd AND control"'


# ── broaden_ladder ────────────────────────────────────────────────────────────


def test_ladder_walks_back_up_the_funnel():
    q = 'host.hostname:WIN01 AND user.name:jdoe AND process.command_line:"psexec.exe"'
    rungs = broaden_ladder(q)
    assert rungs[0] == "host.hostname:WIN01 AND user.name:jdoe"
    assert rungs[1] == "host.hostname:WIN01"
    # Broadest rung must cross artifact types via message:, which every event has.
    assert rungs[-1] == "message:*psexec.exe*"


def test_final_rung_abandons_the_field_constraint():
    """The point of the last rung: reach evidence in types lacking that field."""
    rungs = broaden_ladder('process.command_line:"rundll32.exe evil.dll"')
    assert rungs[-1].startswith("message:"), rungs
    assert "process.command_line" not in rungs[-1]


def test_ladder_is_strictly_broadening_and_has_no_duplicates():
    rungs = broaden_ladder('a:1 AND b:2 AND c:"x"')
    assert len(rungs) == len(set(rungs)), rungs


def test_already_broad_query_gets_no_pointless_rungs():
    """A single already-broad clause should not be re-searched as itself."""
    rungs = broaden_ladder("artifact_type:evtx")
    assert "artifact_type:evtx" not in rungs


def test_ladder_respects_max_rungs():
    q = " AND ".join(f"f{i}:{i}" for i in range(10))
    assert len(broaden_ladder(q, max_rungs=2)) <= 3  # 2 rungs + the message: rung


def test_ladder_handles_empty_query():
    assert broaden_ladder("") == []


# ── coverage_warning ──────────────────────────────────────────────────────────

TOTAL = 1_000_000


def _cov(**fields):
    cov = {"__total__": {"docs": TOTAL, "types": ["evtx", "syslog", "mft", "prefetch", "browser"]}}
    cov.update(fields)
    return cov


def test_sparse_field_warns_and_names_what_was_excluded():
    """The agent must be told those events were excluded, not absent."""
    cov = _cov(
        **{
            "process.command_line": {
                "docs": 20_000,
                "fraction": 0.02,
                "types": ["evtx"],
                "missing_types": ["syslog", "mft", "prefetch", "browser"],
            }
        }
    )
    note = coverage_warning(["process.command_line"], cov, TOTAL)
    assert note is not None
    assert "2.0%" in note
    assert "syslog" in note and "mft" in note
    assert "excluded, not absent" in note
    # It must steer toward a field that can actually see the rest.
    assert "message:" in note


def test_absent_field_says_the_query_can_never_match():
    cov = _cov(
        **{
            "registry.key_path": {
                "docs": 0,
                "fraction": 0.0,
                "types": [],
                "missing_types": ["evtx", "syslog", "mft"],
            }
        }
    )
    note = coverage_warning(["registry.key_path"], cov, TOTAL)
    assert note is not None
    assert "NO event" in note
    assert "only ever return 0 hits" in note


def test_dense_field_produces_no_warning():
    """Warning on a well-populated field would be noise the agent learns to ignore."""
    cov = _cov(
        **{
            "host.hostname": {
                "docs": 990_000,
                "fraction": 0.99,
                "types": ["evtx", "syslog", "mft", "prefetch", "browser"],
                "missing_types": [],
            }
        }
    )
    assert coverage_warning(["host.hostname"], cov, TOTAL) is None


def test_threshold_boundary_is_not_warned():
    cov = _cov(
        **{
            "user.name": {
                "docs": int(TOTAL * SPARSE_FRACTION),
                "fraction": SPARSE_FRACTION,
                "types": ["evtx"],
                "missing_types": ["mft"],
            }
        }
    )
    assert coverage_warning(["user.name"], cov, TOTAL) is None


def test_multiple_sparse_fields_are_all_reported():
    cov = _cov(
        **{
            "process.command_line": {
                "docs": 100,
                "fraction": 0.0001,
                "types": ["evtx"],
                "missing_types": ["syslog"],
            },
            "registry.key_path": {
                "docs": 50,
                "fraction": 0.00005,
                "types": ["registry"],
                "missing_types": ["syslog"],
            },
        }
    )
    note = coverage_warning(["process.command_line", "registry.key_path"], cov, TOTAL)
    assert "process.command_line" in note and "registry.key_path" in note


def test_no_warning_without_inputs():
    assert coverage_warning([], {}, TOTAL) is None
    assert coverage_warning(["a"], {}, TOTAL) is None
    assert coverage_warning(["a"], _cov(), 0) is None


def test_usable_ceiling_is_a_sane_bound():
    """Guards the constant the broaden loop uses to decide a result is readable."""
    assert 100 <= USABLE_HIT_CEILING <= 100_000


if __name__ == "__main__":
    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        globals()[name]()
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
