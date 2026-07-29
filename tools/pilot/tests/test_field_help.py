#!/usr/bin/env python3
"""Tests for tools/pilot/pilot/field_help.py.

Two behaviours, both aimed at the agent burning steps on queries that cannot
match. The tests are deliberately hostile about FALSE corrections: telling the
agent a real field does not exist is worse than saying nothing, because it will
then avoid the one field that would have answered the question.

Pure stdlib. Runs under pytest and standalone.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pilot"))

import field_help as fh  # noqa: E402

# A realistic slice of a Windows-triage case.
KNOWN = {
    "artifact_type", "timestamp", "message",
    "host.hostname", "host.ip", "host.domain",
    "user.name", "user.domain", "user.sid",
    "process.name", "process.command_line", "process.path", "process.parent_name",
    "network.src_ip", "network.dst_ip", "network.dst_port", "network.src_port",
    "evtx.event_id", "evtx.channel",
    "evtx.event_data.CommandLine", "evtx.event_data.LogonType",
    "evtx.event_data.TargetUserName",
    "registry.key_path", "registry.matched_value",
    "mft.filepath", "mft.filename",
    "prefetch.executable_name", "prefetch.run_count", "prefetch.last_run_times",
    "zeek.query", "zeek.log_type",
}


# ── parsing fields out of a query ────────────────────────────────────────────


def test_extracts_fields_in_order():
    q = "evtx.event_id:4688 AND process.command_line:*vssadmin* OR host.hostname:WS01"
    assert fh.query_fields(q) == [
        "evtx.event_id", "process.command_line", "host.hostname"]


def test_boolean_operators_are_not_fields():
    assert fh.query_fields("a:1 AND b:2 OR NOT c:3") == ["a", "b", "c"]


def test_colon_inside_a_quoted_value_is_not_a_field():
    """`message:"a:b"` references ONE field. Treating `a` as a second field would
    produce a fabricated error about a field the analyst never named."""
    assert fh.query_fields('message:"LogonType:10"') == ["message"]


def test_colon_inside_a_regexp_literal_is_not_a_field():
    assert fh.query_fields(r"zeek.query:/.*http:\/\/.*/") == ["zeek.query"]


def test_negated_and_parenthesised_clauses_are_seen():
    q = "(process.name:cmd.exe OR -user.name:SYSTEM) AND evtx.channel:Security"
    got = fh.query_fields(q)
    assert set(got) == {"process.name", "user.name", "evtx.channel"}


def test_empty_query_is_handled():
    assert fh.query_fields("") == [] and fh.query_fields(None) == []


# ── not accusing real fields ─────────────────────────────────────────────────


def test_a_valid_query_produces_no_hint():
    q = "evtx.event_id:4688 AND process.command_line:*vssadmin*"
    assert fh.unknown_fields(q, KNOWN) == []
    assert fh.unknown_field_hint(q, KNOWN) == ""


def test_keyword_and_ci_subfields_are_not_flagged():
    """These are created by the mapping, not listed as separate fields. Flagging
    them would be a confident, wrong correction."""
    q = "process.command_line.ci:*-enc* AND host.hostname.keyword:WS01"
    assert fh.unknown_fields(q, KNOWN) == []


def test_no_accusation_when_the_field_set_is_unknown():
    """An empty field set means the mapping lookup failed — not that every field
    is invalid."""
    assert fh.unknown_fields("anything:1", set()) == []
    assert fh.unknown_field_hint("anything:1", set()) == ""


# ── catching the real mistakes ───────────────────────────────────────────────


def test_wrong_namespace_suggests_the_right_one():
    """The actual bug from the zeek/suricata packs: right leaf, wrong namespace."""
    unknown = fh.unknown_fields("suricata.dst_port:443", KNOWN)
    assert len(unknown) == 1
    field, suggestions = unknown[0]
    assert field == "suricata.dst_port"
    assert "network.dst_port" in suggestions, suggestions


def test_invented_leaf_suggests_the_real_one_in_the_same_namespace():
    unknown = fh.unknown_fields("prefetch.name:POWERSHELL*", KNOWN)
    field, suggestions = unknown[0]
    assert field == "prefetch.name"
    assert any(s.startswith("prefetch.") for s in suggestions), suggestions


def test_underscore_slip_is_caught():
    """mft.file_path vs mft.filepath — the mistake shipped in a previous PR."""
    unknown = fh.unknown_fields("mft.file_path:*Windows*", KNOWN)
    assert unknown and unknown[0][0] == "mft.file_path"
    assert "mft.filepath" in unknown[0][1], unknown[0][1]


def test_hint_explains_that_zero_hits_is_the_field_not_the_evidence():
    hint = fh.unknown_field_hint("registry.key:*Run*", KNOWN)
    assert "does not exist" in hint
    assert "registry.key_path" in hint
    assert "not an absence of evidence" in hint, \
        "the agent must not read a field error as 'nothing happened'"


def test_unknown_field_with_no_plausible_match_still_reports():
    hint = fh.unknown_field_hint("quantum.flux:1", KNOWN)
    assert "does not exist in this case" in hint


def test_multiple_unknown_fields_are_all_reported():
    unknown = fh.unknown_fields("prefetch.name:a AND mft.file_path:b", KNOWN)
    assert {u[0] for u in unknown} == {"prefetch.name", "mft.file_path"}


def test_near_miss_does_not_equate_different_real_fields():
    """prefetch.last_run and prefetch.last_run_times differ by more than a typo;
    suggesting is fine, but `_close` must not call them the same field."""
    assert not fh._close("last_run", "last_run_times")
    assert fh._close("filepath", "filepath")
    assert fh._close("dst_port", "dstport")      # one deletion
    assert fh._close("hostname", "hostnama")     # one substitution


# ── the prompt field list ────────────────────────────────────────────────────


def _many(n: int) -> list[str]:
    return sorted(f"evtx.event_data.Field{i:03d}" for i in range(n))


def test_short_list_is_returned_whole():
    fields = sorted(KNOWN)
    text, shown, total = fh.prompt_field_list(fields, budget=100_000)
    assert shown == total == len(fields)
    assert text.count(", ") == len(fields) - 1


def test_truncation_never_cuts_a_field_name():
    """The bug this exists for: ', '.join(fields)[:3500] sliced the joined STRING,
    leaving a corrupted final entry that the agent was told to use."""
    fields = _many(400)
    text, shown, total = fh.prompt_field_list(fields, budget=3500)
    assert total == 400 and shown < total, "a 400-field case must truncate"
    assert len(text) <= 3500
    for name in text.split(", "):
        assert name in fields, f"corrupted field name in output: {name!r}"


def test_truncation_reports_how_many_were_omitted():
    _, shown, total = fh.prompt_field_list(_many(400), budget=3500)
    assert total - shown > 0, "caller needs the omission count to avoid claiming completeness"


def test_populated_fields_survive_truncation():
    """Alphabetical truncation deleted registry.*, user.* and zeek.* wholesale
    while keeping empty evtx.event_data.A… fields. Density ordering fixes that."""
    fields = sorted([*_many(300), "zeek.query", "user.name", "registry.key_path"])
    density = [
        {"field": "user.name", "count": 90_000},
        {"field": "registry.key_path", "count": 40_000},
        {"field": "zeek.query", "count": 10_000},
    ]
    text, shown, _ = fh.prompt_field_list(fields, density=density, budget=600)
    kept = text.split(", ")
    assert kept[:3] == ["user.name", "registry.key_path", "zeek.query"], kept[:3]
    assert shown == len(kept)


def test_density_fields_absent_from_the_mapping_are_ignored():
    """A density probe lists candidate fields; some may not exist on this case."""
    text, shown, _ = fh.prompt_field_list(
        ["a.b", "c.d"], density=[{"field": "not.here", "count": 5}], budget=1000)
    assert "not.here" not in text and shown == 2


def test_empty_input_is_safe():
    assert fh.prompt_field_list([], budget=3500) == ("", 0, 0)


def test_zero_count_density_entries_do_not_win_ordering():
    fields = ["aaa.bbb", "zzz.yyy"]
    text, _, _ = fh.prompt_field_list(
        fields, density=[{"field": "zzz.yyy", "count": 0}], budget=1000)
    assert text.split(", ")[0] == "aaa.bbb", "an unpopulated field must not be promoted"


# ── standalone runner ────────────────────────────────────────────────────────
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
    print(f"{len(fns)}/{len(fns)} passed (autopilot field help)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
