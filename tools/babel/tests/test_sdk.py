"""The authoring SDK must produce a real BasePlugin the loader can use."""
from __future__ import annotations

from citadel_contracts import BasePlugin, PluginContext
from citadel_contracts.sdk import event, parser


@parser(name="sdk_demo", extensions=[".log"], artifact_type="sdk_demo")
def _parse(ctx):
    for line in ctx.lines():
        if line.strip():
            yield event(timestamp=line[:19], message=line, host={"hostname": "h"})


def test_decorator_makes_baseplugin():
    assert issubclass(_parse, BasePlugin)
    assert _parse.PLUGIN_NAME == "sdk_demo"
    assert ".log" in _parse.SUPPORTED_EXTENSIONS


def test_can_handle_and_get_info():
    from pathlib import Path

    assert _parse.can_handle(Path("x.log"), "text/plain")
    info = _parse.get_info()
    assert info["name"] == "sdk_demo"


def test_parse_yields_contract_events(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("2026-06-11T10:00:00 hello\n\n2026-06-11T10:00:01 world\n")
    ctx = PluginContext(case_id="c", job_id="j", source_file_path=f, source_minio_url="")
    events = list(_parse(ctx).parse())
    assert len(events) == 2
    e = events[0]
    assert e["timestamp"].endswith("Z")          # iso_z canonicalized
    assert e["artifact_type"] == "sdk_demo"        # defaulted from decorator
    assert e["host"] == {"hostname": "h"}
    assert "raw" in e
