"""Tests for text-log coverage: rotated/ISO syslog, generic timestamped logs,
APT history — plus transparent .gz handling. Guards the routing so these stop
landing as 'file'/'generic_text' blobs."""
from __future__ import annotations

import gzip
import uuid
from pathlib import Path

from babel.base_plugin import PluginContext
from babel.syslog.syslog_plugin import SyslogPlugin
from babel.timestamped_log.timestamped_log_plugin import TimestampedLogPlugin
from babel.apt_history.apt_history_plugin import AptHistoryPlugin

KERN = (
    "2026-05-31T00:00:40.248878+02:00 master2 kernel: nftables-drop: IN=ens2 OUT= MAC=de\n"
    "2026-05-31T00:00:41.100000+02:00 master2 systemd[1]: Started session.\n"
)
CLICKHOUSE = (
    "2026.04.06 18:36:43.529137 [ 457282 ] {} <Debug> FakeDiskTransaction: Creating\n"
    "2026.04.06 18:36:43.531941 [ 457282 ] {} <Error> ConfigReloader: Error loading config\n"
    "0. DB::Exception::Exception @ 0x00000000166dc66a\n"
    "1. DB::Exception::Exception @ 0x000000000e55bf0e\n"
    "2026.04.06 18:36:44.000000 [ 457282 ] {} <Trace> MergedBlockOutputStream: done\n"
)
APT = (
    "Start-Date: 2026-06-02  06:27:19\n"
    "Commandline: /usr/bin/unattended-upgrade\n"
    "Upgrade: nginx:amd64 (1.24.0-2ubuntu7.8, 1.24.0-2ubuntu7.9), nginx-common:amd64 (1.24.0-2ubuntu7.8, 1.24.0-2ubuntu7.9)\n"
    "End-Date: 2026-06-02  06:27:28\n"
    "\n"
    "Start-Date: 2026-06-04  06:42:13\n"
    "Commandline: /usr/bin/unattended-upgrade\n"
    "Install: linux-headers-6.8.0-124-generic:amd64 (6.8.0-124.124, automatic)\n"
    "Remove: linux-headers-6.8.0-117-generic:amd64 (6.8.0-117.117)\n"
    "End-Date: 2026-06-04  06:42:36\n"
)


def _run(plugin_cls, path: Path):
    ctx = PluginContext(case_id="c", job_id="j", source_file_path=path, source_minio_url="")
    return list(plugin_cls(ctx).parse())


# ── Syslog: rotated + ISO rsyslog ───────────────────────────────────────────
def test_syslog_claims_rotated_kernel_log(tmp_path):
    f = tmp_path / "kern.log.1"
    f.write_text(KERN)
    assert SyslogPlugin.can_handle(f, "text/plain")
    events = _run(SyslogPlugin, f)
    assert len(events) == 2
    e = events[0]
    assert e["artifact_type"] == "kern_log"
    assert e["timestamp"].startswith("2026-05-31T")
    assert e["host"]["hostname"] == "master2"
    assert e["process"]["name"] == "kernel"


def test_syslog_reads_gz(tmp_path):
    f = tmp_path / "kern.log.2.gz"
    f.write_bytes(gzip.compress(KERN.encode()))
    assert SyslogPlugin.can_handle(f, "application/gzip")
    events = _run(SyslogPlugin, f)
    assert len(events) == 2
    assert events[0]["artifact_type"] == "kern_log"


# ── Timestamped generic log (ClickHouse) ────────────────────────────────────
def test_timestamped_clickhouse(tmp_path):
    f = tmp_path / "clickhouse-server.log"
    f.write_text(CLICKHOUSE)
    assert TimestampedLogPlugin.can_handle(f, "text/plain")
    events = _run(TimestampedLogPlugin, f)
    # 3 timestamped lines; the two tsless stack frames fold into event #2.
    assert len(events) == 3
    assert events[0]["log_file"]["level"] == "DEBUG"
    assert events[1]["log_file"]["level"] == "ERROR"
    assert events[1]["log_file"]["lines"] == 3  # error line + 2 folded frames
    assert all(e["timestamp"].startswith("2026-04-06T") for e in events)


def test_timestamped_rejects_json(tmp_path):
    f = tmp_path / "data.log"
    f.write_text('{"a":1}\n{"b":2}\n')
    assert TimestampedLogPlugin.can_handle(f, "text/plain") is False


# ── APT history ─────────────────────────────────────────────────────────────
def test_apt_history(tmp_path):
    f = tmp_path / "history.log"
    f.write_text(APT)
    assert AptHistoryPlugin.can_handle(f, "text/plain")
    events = _run(AptHistoryPlugin, f)
    assert len(events) == 2
    up, ins = events
    assert up["artifact_type"] == "package_event"
    assert up["timestamp"].startswith("2026-06-02T")
    assert "Upgrade" in up["package_event"]["actions"]
    assert "nginx" in up["package_event"]["packages"]
    assert set(ins["package_event"]["actions"]) == {"Install", "Remove"}


def test_apt_history_gz(tmp_path):
    f = tmp_path / "history.log.7.gz"
    f.write_bytes(gzip.compress(APT.encode()))
    assert AptHistoryPlugin.can_handle(f, "application/gzip")
    assert len(_run(AptHistoryPlugin, f)) == 2
