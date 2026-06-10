"""Tests for the lastlog binary parser."""
from __future__ import annotations

import struct

from babel.base_plugin import PluginContext
from babel.lastlog.lastlog_plugin import LastlogPlugin

_REC = struct.Struct("<i32s256s")


def _record(ll_time: int, line: str, host: str) -> bytes:
    return _REC.pack(ll_time, line.encode().ljust(32, b"\x00"), host.encode().ljust(256, b"\x00"))


def _build(tmp_path):
    # UID 0: never logged in (all zero) → skipped.
    # UID 1: login from an IP. UID 2: login from a hostname.
    data = (
        _REC.pack(0, b"\x00" * 32, b"\x00" * 256)
        + _record(1717000000, "pts/0", "213.36.7.8")
        + _record(1717000500, "pts/3", "workstation.corp")
    )
    f = tmp_path / "lastlog"
    f.write_bytes(data)
    return f


def test_lastlog_parses_records(tmp_path):
    f = _build(tmp_path)
    assert LastlogPlugin.can_handle(f, "application/octet-stream")
    ctx = PluginContext(case_id="c", job_id="j", source_file_path=f, source_minio_url="")
    events = list(LastlogPlugin(ctx).parse())
    assert len(events) == 2  # UID 0 skipped

    ip = events[0]
    assert ip["artifact_type"] == "login_event"
    assert ip["login_event"]["uid"] == 1
    assert ip["login_event"]["tty"] == "pts/0"
    assert ip["network"]["src_ip"] == "213.36.7.8"
    assert ip["timestamp"].endswith("Z")

    host = events[1]
    assert host["login_event"]["uid"] == 2
    assert host["login_event"]["source"] == "workstation.corp"


def test_lastlog_rejects_non_lastlog(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_bytes(b"hello")
    assert LastlogPlugin.can_handle(f, "text/plain") is False


def test_lastlog_rejects_misaligned(tmp_path):
    f = tmp_path / "lastlog"
    f.write_bytes(b"\x00" * 100)  # not a multiple of 292
    assert LastlogPlugin.can_handle(f, "application/octet-stream") is False
