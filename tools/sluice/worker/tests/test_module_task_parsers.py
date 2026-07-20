"""Robustness tests for the forensic-artifact parsers in tasks/module_task.py.

These parsers run over attacker-touched evidence (EVTX exports, registry
hives, LNK/prefetch files, Hayabusa/RegRipper/Hindsight tool output) that a
compromised host may have deliberately mangled. Each parser must:
  * produce the expected normalized hit(s) on a small representative input, and
  * never raise on empty / truncated / wrong-shaped / non-UTF8 / hostile input
    — it must instead skip the bad record and return whatever it could salvage
    (typically ``[]``).

Requires `celery` + `citadel_contracts` (module_task's hard, non-lazy import
chain) to be importable; skips cleanly if the environment doesn't have them,
same as the module's own optional-dependency parsers (EVTX/registry/LNK) skip
when their libraries are absent.
"""

from __future__ import annotations

import struct
import sys
from datetime import datetime
from pathlib import Path

import pytest

pytest.importorskip("celery")

_WORKER_ROOT = Path(__file__).resolve().parents[1]
_TASKS_DIR = _WORKER_ROOT / "tasks"
_TOOLS_DIR = _WORKER_ROOT.parents[1]  # tools/sluice/worker -> tools/

for _p in (str(_WORKER_ROOT), str(_TASKS_DIR), str(_TOOLS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import module_task as mt
except ModuleNotFoundError:
    pytest.skip("module_task's hard dependency chain is unavailable", allow_module_level=True)


# ── _normalize_ts ─────────────────────────────────────────────────────────────


def test_normalize_ts_happy_path():
    assert mt._normalize_ts("2024-01-15 10:30:00.123") == "2024-01-15T10:30:00.123Z"
    assert mt._normalize_ts("2024-01-15T10:30:00+00:00") == "2024-01-15T10:30:00Z"


@pytest.mark.parametrize(
    "bad",
    ["", None, "garbage", "20", "2024-01-15", "\x00\x01binary", "9" * 500],
)
def test_normalize_ts_never_raises(bad):
    result = mt._normalize_ts(bad)
    assert isinstance(result, str)


# ── _hayabusa_row_to_hit ──────────────────────────────────────────────────────


def test_hayabusa_row_to_hit_happy_path():
    row = {
        "Timestamp": "2024-03-01 12:00:00.000 +00:00",
        "RuleTitle": "Suspicious PowerShell",
        "Level": "high",
        "Computer": "WIN-HOST01",
        "Channel": "Microsoft-Windows-PowerShell/Operational",
        "EventID": "4104",
        "Details": {"ScriptBlockText": "IEX (New-Object Net.WebClient)...", "empty": "-"},
        "RuleFile": "susp_ps.yml",
        "EvtxFile": "PowerShell.evtx",
    }
    hit = mt._hayabusa_row_to_hit(row)
    assert hit is not None
    assert hit["rule_title"] == "Suspicious PowerShell"
    assert hit["level"] == "high"
    assert hit["level_int"] == mt.LEVEL_INT["high"]
    assert hit["computer"] == "WIN-HOST01"
    assert hit["event_id"] == 4104
    assert "ScriptBlockText" in hit["details_raw"]
    assert "empty" not in hit["details_raw"]  # "-" values are dropped


def test_hayabusa_row_to_hit_no_title_or_timestamp_returns_none():
    assert mt._hayabusa_row_to_hit({}) is None
    assert mt._hayabusa_row_to_hit({"Computer": "X"}) is None


@pytest.mark.parametrize(
    "row",
    [
        {},
        {"Timestamp": None, "RuleTitle": None},
        {"EventID": "not-a-number", "RuleTitle": "x", "Timestamp": "t"},
        {"EventID": "99999999999999999999999999", "RuleTitle": "x", "Timestamp": "t"},
        {"Details": 12345, "RuleTitle": "x", "Timestamp": "t"},
        {"Details": ["a", "b"], "RuleTitle": "x", "Timestamp": "t"},
        {"Level": None, "RuleTitle": "x", "Timestamp": "t"},
        {"RuleTitle": "x" * 100_000, "Timestamp": "t", "Details": "y" * 100_000},
    ],
)
def test_hayabusa_row_to_hit_malformed_never_raises(row):
    # Must not raise; either a hit dict or None.
    result = mt._hayabusa_row_to_hit(row)
    assert result is None or isinstance(result, dict)


def test_hayabusa_row_to_hit_details_capped_at_2000():
    row = {"RuleTitle": "x", "Timestamp": "t", "Details": "a" * 5000}
    hit = mt._hayabusa_row_to_hit(row)
    assert len(hit["details_raw"]) == 2000


# ── _parse_hayabusa_csv ────────────────────────────────────────────────────────


def test_parse_hayabusa_csv_happy_path(tmp_path):
    csv_text = (
        "Timestamp,RuleTitle,Level,Computer,Channel,EventID,Details,Tags\n"
        '2024-01-01 00:00:00.000 +00:00,Mimikatz Detected,crit,HOST-A,Security,'
        '4688,"CommandLine: mimikatz.exe","attack.credential-access,attack.t1003"\n'
    )
    path = tmp_path / "hayabusa.csv"
    path.write_text(csv_text, encoding="utf-8")
    hits = mt._parse_hayabusa_csv(path)
    assert len(hits) == 1
    hit = hits[0]
    assert hit["rule_title"] == "Mimikatz Detected"
    assert hit["level"] == "critical"
    assert hit["event_id"] == 4688
    assert hit["tags"] == ["attack.credential-access", "attack.t1003"]


def test_parse_hayabusa_csv_empty_file_returns_empty(tmp_path):
    path = tmp_path / "empty.csv"
    path.write_text("", encoding="utf-8")
    assert mt._parse_hayabusa_csv(path) == []


def test_parse_hayabusa_csv_header_only_returns_empty(tmp_path):
    path = tmp_path / "header_only.csv"
    path.write_text("Timestamp,RuleTitle,Level\n", encoding="utf-8")
    assert mt._parse_hayabusa_csv(path) == []


def test_parse_hayabusa_csv_garbage_rows_are_skipped_not_raised(tmp_path):
    # Wrong-shape rows, missing key columns, non-UTF8 bytes, huge numbers.
    path = tmp_path / "garbage.csv"
    with open(path, "wb") as fh:
        fh.write(b"Timestamp,RuleTitle,Level,EventID\n")
        fh.write(b",,,\n")  # blank row -> skipped
        fh.write(b"2024,Real Rule,high,99999999999999999999999999\n")  # huge EventID, kept (Python ints are unbounded)
        fh.write(b"2024,Non Numeric ID,high,not-a-number\n")  # non-numeric EventID -> coerced to None
        fh.write(b"\xff\xfe,garbage\xff,med,abc\n")  # non-utf8 bytes (errors=replace)
        fh.write(b"only,two,cols\n")  # short row (DictReader tolerates via None)
    hits = mt._parse_hayabusa_csv(path)
    assert isinstance(hits, list)
    titles = [h["rule_title"] for h in hits]
    assert "Real Rule" in titles
    assert "Non Numeric ID" in titles
    real = next(h for h in hits if h["rule_title"] == "Real Rule")
    assert real["event_id"] == 99999999999999999999999999
    non_numeric = next(h for h in hits if h["rule_title"] == "Non Numeric ID")
    assert non_numeric["event_id"] is None


def test_parse_hayabusa_csv_nonexistent_file_raises_runtimeerror(tmp_path):
    # Missing file is a real I/O failure, not a malformed record — the parser
    # intentionally raises so the caller surfaces it instead of silently
    # reporting zero hits.
    with pytest.raises(RuntimeError):
        mt._parse_hayabusa_csv(tmp_path / "does_not_exist.csv")


# ── _parse_hayabusa_jsonl ──────────────────────────────────────────────────────


def test_parse_hayabusa_jsonl_happy_path(tmp_path):
    path = tmp_path / "hayabusa.jsonl"
    path.write_text(
        '{"Timestamp": "2024-01-01T00:00:00Z", "RuleTitle": "Test Rule", '
        '"Level": "medium", "Computer": "H1", "EventID": "4624", "Details": {"A": "B"}}\n',
        encoding="utf-8",
    )
    hits = mt._parse_hayabusa_jsonl(path)
    assert len(hits) == 1
    assert hits[0]["rule_title"] == "Test Rule"


def test_parse_hayabusa_jsonl_empty_file_returns_empty(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    assert mt._parse_hayabusa_jsonl(path) == []


def test_parse_hayabusa_jsonl_malformed_lines_are_skipped(tmp_path):
    path = tmp_path / "garbage.jsonl"
    path.write_text(
        "not json at all\n"
        '{"RuleTitle": "Good Row", "Timestamp": "2024-01-01T00:00:00Z"}\n'
        "{broken json,,,\n"
        "[]\n"  # valid JSON, but not a dict -> skipped
        '{"RuleTitle": "Trailing Comma Row", "Timestamp": "t"},\n',
        encoding="utf-8",
    )
    hits = mt._parse_hayabusa_jsonl(path)
    titles = [h["rule_title"] for h in hits]
    assert "Good Row" in titles


def test_parse_hayabusa_jsonl_json_array_format(tmp_path):
    path = tmp_path / "array.json"
    path.write_text(
        '[{"RuleTitle": "Array Rule", "Timestamp": "2024-01-01T00:00:00Z"}]',
        encoding="utf-8",
    )
    hits = mt._parse_hayabusa_jsonl(path)
    assert len(hits) == 1
    assert hits[0]["rule_title"] == "Array Rule"


def test_parse_hayabusa_jsonl_truncated_array_falls_back_gracefully(tmp_path):
    # Truncated JSON array (as if the tool was killed mid-write) must not raise;
    # the parser falls back to line-by-line best-effort decoding.
    path = tmp_path / "truncated_array.json"
    path.write_text(
        '[{"RuleTitle": "Rule A", "Timestamp": "t"},\n{"RuleTitle": "Rule B", "Timestamp": "t"',
        encoding="utf-8",
    )
    hits = mt._parse_hayabusa_jsonl(path)
    assert isinstance(hits, list)


def test_parse_hayabusa_jsonl_binary_garbage_never_raises(tmp_path):
    path = tmp_path / "binary.jsonl"
    path.write_bytes(b"\x00\x01\x02\xff\xfe\xfd not json \x89PNG\r\n")
    hits = mt._parse_hayabusa_jsonl(path)
    assert hits == []


def test_parse_hayabusa_jsonl_missing_file_returns_empty(tmp_path):
    assert mt._parse_hayabusa_jsonl(tmp_path / "missing.jsonl") == []


# ── _hindsight_item_to_hit / _parse_hindsight_timestamp ───────────────────────


def test_hindsight_item_to_hit_happy_path():
    item = {
        "url": "https://example.com/login",
        "title": "Example Login",
        "timestamp_UTC": "2024-01-15 10:00:00.000000",
        "type": "URL Visited",
        "profile": "Default",
    }
    hit = mt._hindsight_item_to_hit(item)
    assert hit is not None
    assert hit["url"] == "https://example.com/login"
    assert hit["rule_title"] == "URL Visited"
    assert hit["computer"] == "Default"


def test_hindsight_item_to_hit_no_url_or_title_returns_none():
    assert mt._hindsight_item_to_hit({}) is None
    assert mt._hindsight_item_to_hit({"type": "x"}) is None


@pytest.mark.parametrize(
    "item",
    [
        {},
        {"url": None, "title": None},
        {"url": 12345},  # non-string url
        {"value": {"nested": "dict"}},
        {"url": "u", "timestamp_UTC": "not-a-timestamp"},
        {"url": "u", "timestamp": -99999999999999999999},
        {"url": "u" * 200_000},
    ],
)
def test_hindsight_item_to_hit_malformed_never_raises(item):
    result = mt._hindsight_item_to_hit(item)
    assert result is None or isinstance(result, dict)


@pytest.mark.parametrize(
    "ts",
    ["", None, 0, "garbage", "2024-01-15 10:00:00.000000", 13495000000000000, -1, "9" * 40],
)
def test_parse_hindsight_timestamp_never_raises(ts):
    result = mt._parse_hindsight_timestamp(ts)
    assert isinstance(result, str)


def test_parse_hindsight_jsonl_malformed_lines_are_skipped(tmp_path):
    path = tmp_path / "hindsight.jsonl"
    path.write_text(
        "not json\n"
        '{"url": "https://good.example", "title": "Good", "type": "URL Visited"}\n'
        "[1, 2, 3]\n"
        "\n",
        encoding="utf-8",
    )
    hits = mt._parse_hindsight_jsonl(path)
    assert len(hits) == 1
    assert hits[0]["url"] == "https://good.example"


def test_parse_hindsight_jsonl_missing_file_returns_empty(tmp_path):
    assert mt._parse_hindsight_jsonl(tmp_path / "missing.jsonl") == []


# ── _parse_regripper_output ────────────────────────────────────────────────────


def test_parse_regripper_output_happy_path():
    output = (
        "----------------------------------------\n"
        "run v.20200522\n"
        "(NTUSER.DAT)\n"
        "RunMRU key values:\n"
        "a: cmd.exe\n"
        "----------------------------------------\n"
        "userassist v.20230518\n"
        "(NTUSER.DAT)\n"
        "Notepad.exe: run 3 times\n"
        "----------------------------------------\n"
    )
    hits = mt._parse_regripper_output(output, "NTUSER.DAT")
    assert len(hits) == 2
    assert hits[0]["rule_title"] == "run"
    assert hits[0]["computer"] == "NTUSER.DAT"
    assert "cmd.exe" in hits[0]["details_raw"]
    assert hits[1]["rule_title"] == "userassist"


@pytest.mark.parametrize(
    "output",
    [
        "",
        "\n\n\n",
        "----------------------------------------\n----------------------------------------\n",
        "no separators just plain text with no dashes at all here",
        "-" * 5,  # too short a separator to match the regex threshold
        "\x00\x01binary garbage\xff\xfe not text",
        "-" * 10_000,  # pathological separator-only content
    ],
)
def test_parse_regripper_output_malformed_never_raises(output):
    hits = mt._parse_regripper_output(output, "SYSTEM")
    assert isinstance(hits, list)


def test_parse_regripper_output_content_capped_at_2000():
    output = "----------------------------------------\n" "plugin v.1\n" + ("x" * 5000) + "\n"
    hits = mt._parse_regripper_output(output, "SYSTEM")
    assert hits
    assert len(hits[0]["details_raw"]) == 2000


# ── _regripper_profile / _hive_type ────────────────────────────────────────────


@pytest.mark.parametrize(
    "filename,expected",
    [
        ("NTUSER.DAT", "ntuser"),
        ("ntuser.dat", "ntuser"),
        ("UsrClass.dat", "ntuser"),  # USRCLASS also routes to ntuser profile
        ("SYSTEM", "system"),
        ("SOFTWARE", "software"),
        ("SAM", "sam"),
        ("SECURITY", "security"),
        ("some_unknown_file.bin", "ntuser"),
        ("", "ntuser"),
    ],
)
def test_regripper_profile_never_raises(filename, expected):
    assert mt._regripper_profile(filename) == expected


@pytest.mark.parametrize(
    "filename,expected",
    [
        ("NTUSER.DAT", "ntuser"),
        ("UsrClass.dat", "usrclass"),
        ("SYSTEM", "system"),
        ("SOFTWARE", "software"),
        ("SAM", "sam"),
        ("SECURITY", "security"),
        ("weird.hive", "ntuser"),
        ("", "ntuser"),
    ],
)
def test_hive_type_never_raises(filename, expected):
    assert mt._hive_type(filename) == expected


# ── _parse_prefetch_triage ─────────────────────────────────────────────────────


def _make_scca_prefetch(tmp_path, version: int, run_count: int | None = None):
    header = bytearray(600)
    struct.pack_into("<I", header, 0, version)
    header[4:8] = b"SCCA"
    if run_count is not None:
        offset = mt._PF_RUN_COUNT_OFFSET[version]
        struct.pack_into("<I", header, offset, run_count)
    path = tmp_path / "NOTEPAD.EXE-AB1234CD.pf"
    path.write_bytes(bytes(header))
    return path


def test_parse_prefetch_triage_happy_path_win10(tmp_path):
    path = _make_scca_prefetch(tmp_path, version=30, run_count=7)
    hits = mt._parse_prefetch_triage(path)
    assert len(hits) == 1
    hit = hits[0]
    assert hit["rule_title"] == "Prefetch: NOTEPAD.EXE"
    assert "hash=AB1234CD" in hit["details_raw"]
    assert "run_count=7" in hit["details_raw"]
    assert "Win10" in hit["details_raw"]


def test_parse_prefetch_triage_mam_compressed(tmp_path):
    path = tmp_path / "CMD.EXE-11112222.pf"
    path.write_bytes(b"MAM" + b"\x00" * 509)
    hits = mt._parse_prefetch_triage(path)
    assert len(hits) == 1
    assert "MAM-compressed" in hits[0]["details_raw"]


@pytest.mark.parametrize(
    "content,name",
    [
        (b"", "EMPTY-00000000.pf"),
        (b"\x00" * 10, "TINY-00000000.pf"),
        (b"random garbage not a prefetch file at all" * 20, "GARBAGE-00000000.pf"),
        (b"SCCA" * 200, "NOSCCAMAGIC-00000000.pf"),  # wrong offset for signature
        (b"no-dash-name-at-all.pf", "no-dash-name-at-all.pf"),
    ],
)
def test_parse_prefetch_triage_malformed_never_raises(tmp_path, content, name):
    path = tmp_path / name
    path.write_bytes(content)
    hits = mt._parse_prefetch_triage(path)
    assert isinstance(hits, list)
    assert len(hits) == 1  # prefetch parser always returns exactly one summary hit


def test_parse_prefetch_triage_unknown_version_still_returns_hit(tmp_path):
    header = bytearray(600)
    struct.pack_into("<I", header, 0, 999)  # unknown SCCA version
    header[4:8] = b"SCCA"
    path = tmp_path / "APP.EXE-DEADBEEF.pf"
    path.write_bytes(bytes(header))
    hits = mt._parse_prefetch_triage(path)
    assert len(hits) == 1
    assert "v999" in hits[0]["details_raw"]


def test_parse_prefetch_triage_missing_file_never_raises(tmp_path):
    hits = mt._parse_prefetch_triage(tmp_path / "does_not_exist-00000000.pf")
    assert isinstance(hits, list)
    assert len(hits) == 1  # stat() failure is swallowed; mtime falls back to ""
    assert hits[0]["timestamp"] == ""


# ── _parse_lnk_triage ──────────────────────────────────────────────────────────


def test_parse_lnk_triage_missing_dependency_or_garbage_never_raises(tmp_path):
    path = tmp_path / "shortcut.lnk"
    path.write_bytes(b"not a real lnk file" * 10)
    hits = mt._parse_lnk_triage(path)
    assert hits == []  # LnkParse3 either absent or fails to parse garbage -> []


def test_parse_lnk_triage_empty_file_never_raises(tmp_path):
    path = tmp_path / "empty.lnk"
    path.write_bytes(b"")
    hits = mt._parse_lnk_triage(path)
    assert hits == []


def test_parse_lnk_triage_datetime_timestamp_normalized(monkeypatch, tmp_path):
    # Exercise the datetime-object branch without requiring LnkParse3 to be
    # installed: monkeypatch the module import via sys.modules.
    import types

    fake_lnkparse3 = types.ModuleType("LnkParse3")

    class _FakeLnk:
        def __init__(self, fh):
            pass

        def get_json(self):
            return {
                "header": {"creation_time": datetime(2024, 1, 1, 12, 0, 0)},
                "link_info": {"local_base_path": "C:\\evil.exe"},
                "string_data": {"machine_identifier": "WIN-HOST"},
            }

    fake_lnkparse3.lnk_file = _FakeLnk
    monkeypatch.setitem(sys.modules, "LnkParse3", fake_lnkparse3)

    path = tmp_path / "evil.lnk"
    path.write_bytes(b"\x00" * 4)
    hits = mt._parse_lnk_triage(path)
    assert len(hits) == 1
    assert hits[0]["timestamp"] == "2024-01-01T12:00:00Z"
    assert "evil.exe" in hits[0]["details_raw"]
    assert hits[0]["computer"] == "WIN-HOST"


# ── _parse_evtx_triage / _parse_registry_triage (optional-dep guarded) ────────


def test_parse_evtx_triage_missing_dependency_or_garbage_never_raises(tmp_path):
    path = tmp_path / "fake.evtx"
    path.write_bytes(b"not a real evtx file" * 50)
    hits = mt._parse_evtx_triage(path)
    assert hits == []


def test_parse_evtx_triage_empty_file_never_raises(tmp_path):
    path = tmp_path / "empty.evtx"
    path.write_bytes(b"")
    assert mt._parse_evtx_triage(path) == []


def test_parse_registry_triage_missing_dependency_or_garbage_never_raises(tmp_path):
    path = tmp_path / "SYSTEM"
    path.write_bytes(b"not a real hive" * 50)
    hits = mt._parse_registry_triage(path)
    assert hits == []


def test_parse_registry_triage_unknown_hive_type_returns_empty(tmp_path):
    # _hive_type() falls back to "ntuser" for unrecognised names, and the
    # "security" hive type has an explicit empty triage-path list — both must
    # short-circuit to [] without ever touching the (garbage) file bytes.
    path = tmp_path / "SECURITY"
    path.write_bytes(b"garbage")
    assert mt._parse_registry_triage(path) == []
