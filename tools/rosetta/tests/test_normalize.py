"""Tests for Rosetta ForensicEvent -> ECS v8 normalization."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from rosetta.normalize import load_fieldmap, normalize_event


@pytest.fixture(scope="module")
def fieldmap():
    return load_fieldmap()


def test_evtx_event_maps_to_ecs(fieldmap):
    """An EVTX-style windows_event -> ECS process category + winlog/user fields."""
    event = {
        "timestamp": "2026-01-02T03:04:05Z",
        "message": "A new process has been created.",
        "artifact_type": "windows_event",
        "timestamp_desc": "logon",
        "os": "windows",
        "source_path": "C:/Windows/System32/winevt/Logs/Security.evtx",
        "parser": "evtx",
        "raw": {
            "EventID": 4688,
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Channel": "Security",
            "Computer": "WIN-DC01",
            "TargetUserName": "jdoe",
            "TargetDomainName": "CORP",
            "ProcessName": "cmd.exe",
            "ProcessId": 4242,
            "CommandLine": "cmd.exe /c whoami",
            "IpAddress": "10.0.0.5",
            "IpPort": 49210,
        },
    }
    doc = normalize_event(event, fieldmap, ecs_version="8.11")

    assert doc["@timestamp"] == "2026-01-02T03:04:05Z"
    assert doc["ecs"]["version"] == "8.11"
    assert doc["event"]["category"] == ["process"]
    assert doc["event"]["action"] == "logon"
    assert doc["message"] == "A new process has been created."
    assert doc["host"]["name"] == "WIN-DC01"
    assert doc["host"]["os"]["type"] == "windows"
    assert doc["user"]["name"] == "jdoe"
    assert doc["user"]["domain"] == "CORP"
    assert doc["process"]["name"] == "cmd.exe"
    assert doc["process"]["pid"] == 4242
    assert doc["process"]["command_line"] == "cmd.exe /c whoami"
    assert doc["event"]["code"] == 4688
    assert doc["winlog"]["channel"] == "Security"
    assert doc["source"]["ip"] == "10.0.0.5"
    assert doc["source"]["port"] == 49210
    assert doc["log"]["file"]["path"].endswith("Security.evtx")
    # raw retention
    assert doc["citadel"]["raw"]["EventID"] == 4688


def test_syslog_event_maps_to_ecs(fieldmap):
    """A syslog-style event -> ECS host category + process/host fields."""
    event = {
        "timestamp": "2026-03-04T05:06:07Z",
        "message": "sshd[1234]: Accepted password for root from 192.0.2.1",
        "artifact_type": "syslog",
        "timestamp_desc": "event",
        "os": "linux",
        "raw": {
            "hostname": "web-01",
            "program": "sshd",
            "pid": 1234,
            "facility": "auth",
            "severity": "info",
            "user": "root",
        },
    }
    doc = normalize_event(event, fieldmap)

    assert doc["@timestamp"] == "2026-03-04T05:06:07Z"
    assert doc["ecs"]["version"] == "8.11"
    assert doc["event"]["category"] == ["host"]
    assert doc["event"]["type"] == ["info"]
    assert doc["host"]["name"] == "web-01"
    assert doc["host"]["os"]["type"] == "linux"
    assert doc["process"]["name"] == "sshd"
    assert doc["process"]["pid"] == 1234
    assert doc["user"]["name"] == "root"
    assert doc["log"]["syslog"]["facility"]["name"] == "auth"
    assert doc["log"]["syslog"]["severity"]["name"] == "info"
    assert doc["citadel"]["raw"]["program"] == "sshd"


def test_unknown_artifact_type_falls_back(fieldmap):
    """Unknown artifact_type still produces a valid ECS skeleton."""
    event = {"timestamp": "2026-01-01T00:00:00Z", "message": "mystery", "artifact_type": "nope"}
    doc = normalize_event(event, fieldmap)
    assert doc["@timestamp"] == "2026-01-01T00:00:00Z"
    assert doc["ecs"]["version"] == "8.11"
    assert doc["message"] == "mystery"
    assert "category" not in doc.get("event", {})


def test_string_raw_is_retained(fieldmap):
    event = {
        "timestamp": "2026-01-01T00:00:00Z",
        "message": "raw string event",
        "artifact_type": "syslog",
        "raw": "Jan  1 00:00:00 web-01 sshd[1]: started",
    }
    doc = normalize_event(event, fieldmap)
    assert doc["citadel"]["raw"] == "Jan  1 00:00:00 web-01 sshd[1]: started"


def test_ecs_version_override(fieldmap):
    event = {"timestamp": "2026-01-01T00:00:00Z", "message": "x", "artifact_type": "syslog"}
    doc = normalize_event(event, fieldmap, ecs_version="8.6")
    assert doc["ecs"]["version"] == "8.6"


def test_cli_end_to_end(tmp_path):
    """Run the installed-style CLI module on a tiny EVTX + syslog sample."""
    events = [
        {
            "timestamp": "2026-01-02T03:04:05Z",
            "message": "process created",
            "artifact_type": "windows_event",
            "raw": {"EventID": 4688, "Computer": "WIN-DC01", "ProcessName": "cmd.exe"},
        },
        {
            "timestamp": "2026-03-04T05:06:07Z",
            "message": "ssh login",
            "artifact_type": "syslog",
            "raw": {"hostname": "web-01", "program": "sshd"},
        },
    ]
    inp = tmp_path / "events.jsonl"
    out = tmp_path / "ecs.jsonl"
    inp.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    repo_root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "rosetta.cli",
            "normalize",
            str(inp),
            "--ecs",
            "8.11",
            "-o",
            str(out),
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    d0, d1 = json.loads(lines[0]), json.loads(lines[1])
    assert d0["event"]["category"] == ["process"]
    assert d0["host"]["name"] == "WIN-DC01"
    assert d1["event"]["category"] == ["host"]
    assert d1["process"]["name"] == "sshd"
    assert d0["ecs"]["version"] == "8.11"
