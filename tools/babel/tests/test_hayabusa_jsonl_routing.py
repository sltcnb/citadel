"""Hayabusa JSONL routing regression.

The hayabusa plugin used to claim EVERY .jsonl file by extension alone, and
its alphabetical load order puts it before the generic ndjson plugin — so a
plain JSON-lines upload was routed to hayabusa and silently produced 0 events.

can_handle() must now sniff the first non-empty line: only JSON objects with
Hayabusa markers (RuleTitle/ruleTitle, or Level + EvtxFile/RuleFile) are
claimed. Generic .jsonl stays with ndjson.
"""

import json
import logging
import sys
from pathlib import Path

PLUGINS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGINS.parent))  # tools/ for `babel` pkg
sys.path.insert(0, str(PLUGINS))

from babel.base_plugin import PluginContext  # noqa: E402
from babel.hayabusa.hayabusa_plugin import HayabusaPlugin  # noqa: E402
from babel.ndjson.ndjson_plugin import NdjsonPlugin  # noqa: E402

_HAYABUSA_LINE = json.dumps(
    {
        "Timestamp": "2024-03-01 12:00:00.000 +00:00",
        "RuleTitle": "Suspicious PowerShell",
        "Level": "high",
        "Computer": "WIN-HOST01",
        "Channel": "Security",
        "EventID": 4104,
        "RecordID": 12345,
        "Details": "Logon Type: 3",
        "RuleFile": "susp_ps.yml",
        "EvtxFile": "PowerShell.evtx",
    }
)

_GENERIC_LINES = "\n".join(
    json.dumps({"timestamp": "2024-03-01T12:00:00Z", "message": f"plain log line {i}"})
    for i in range(3)
)


def _ctx(p: Path) -> PluginContext:
    return PluginContext(
        case_id="c",
        job_id="j",
        source_file_path=p,
        source_minio_url=f"file://{p}",
        config={},
        logger=logging.getLogger("t"),
    )


def test_generic_jsonl_not_claimed_by_hayabusa(tmp_path):
    f = tmp_path / "app.jsonl"
    f.write_text(_GENERIC_LINES + "\n")
    assert not HayabusaPlugin.can_handle(f, "application/x-ndjson")
    # ...and the generic ndjson plugin DOES claim it, so routing lands there.
    assert NdjsonPlugin.can_handle(f, "application/x-ndjson")


def test_generic_jsonl_with_level_key_alone_not_claimed(tmp_path):
    # 'Level'/'level' appear in plenty of non-Hayabusa logs — not enough alone.
    f = tmp_path / "levels.jsonl"
    f.write_text(json.dumps({"Level": "info", "message": "hello"}) + "\n")
    assert not HayabusaPlugin.can_handle(f, "application/x-ndjson")


def test_hayabusa_jsonl_claimed_and_parsed(tmp_path):
    f = tmp_path / "hayabusa_results.jsonl"
    f.write_text(_HAYABUSA_LINE + "\n" + _HAYABUSA_LINE + "\n")
    assert HayabusaPlugin.can_handle(f, "application/x-ndjson")
    events = list(HayabusaPlugin(_ctx(f)).parse())
    assert len(events) == 2
    assert events[0]["artifact_type"] == "hayabusa"
    assert events[0]["hayabusa"]["rule_title"] == "Suspicious PowerShell"


def test_hayabusa_jsonl_camelcase_marker_claimed(tmp_path):
    f = tmp_path / "hayabusa_camel.jsonl"
    f.write_text(json.dumps({"ruleTitle": "X", "timestamp": "2024-01-01T00:00:00Z"}) + "\n")
    assert HayabusaPlugin.can_handle(f, "application/x-ndjson")


def test_hayabusa_jsonl_level_plus_evtx_marker_claimed(tmp_path):
    f = tmp_path / "hayabusa_evtx.jsonl"
    f.write_text(json.dumps({"Level": "high", "EvtxFile": "Security.evtx"}) + "\n")
    assert HayabusaPlugin.can_handle(f, "application/x-ndjson")


def test_hayabusa_jsonl_leading_blank_lines_skipped(tmp_path):
    f = tmp_path / "hayabusa_blanks.jsonl"
    f.write_text("\n\n" + _HAYABUSA_LINE + "\n")
    assert HayabusaPlugin.can_handle(f, "application/x-ndjson")


def test_hayabusa_jsonl_rejects_garbage_and_empty(tmp_path):
    garbage = tmp_path / "garbage.jsonl"
    garbage.write_text("this is not json\n")
    assert not HayabusaPlugin.can_handle(garbage, "application/x-ndjson")
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    assert not HayabusaPlugin.can_handle(empty, "application/x-ndjson")


def test_csv_sniffing_unchanged(tmp_path):
    f = tmp_path / "hayabusa_results.csv"
    f.write_text('"Timestamp","RuleTitle","Level","Computer","EvtxFile"\n"x","y","high","h","e"\n')
    assert HayabusaPlugin.can_handle(f, "text/csv")
    not_hayabusa = tmp_path / "other.csv"
    not_hayabusa.write_text("a,b,c\n1,2,3\n")
    assert not HayabusaPlugin.can_handle(not_hayabusa, "text/csv")


if __name__ == "__main__":
    import tempfile

    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        fn = globals()[name]
        with tempfile.TemporaryDirectory() as td:
            fn(Path(td))
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
