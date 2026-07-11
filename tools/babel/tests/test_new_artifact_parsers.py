"""Contract tests for the new artifact parsers.

Each parser must turn its raw artifact into a normalized event carrying the
fields the timeline / report / IOC panel query on (artifact_type, an ISO-Z
timestamp, and its load-bearing nested object). These run WITHOUT the stack —
they prove the parse→indexable-event contract that the (Docker-only) end-to-end
ingest path relies on.
"""
from __future__ import annotations

import base64
import codecs
import json
import sqlite3
import struct
from datetime import datetime, timezone


from babel.base_plugin import PluginContext

_FT = int((datetime(2026, 7, 1, 11, 51, 7, tzinfo=timezone.utc)
           - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)


def _ctx(path):
    return PluginContext(case_id="c", job_id="j", source_file_path=path, source_minio_url="")


# ── Recycle Bin $I ─────────────────────────────────────────────────────────────
def test_recyclebin_i_file(tmp_path):
    from babel.recyclebin.recyclebin_plugin import RecycleBinPlugin
    p = r"C:\Users\aflohic\Downloads\evil.msi"
    enc = p.encode("utf-16-le") + b"\x00\x00"
    buf = struct.pack("<qq", 2, 4238488) + struct.pack("<q", _FT) + struct.pack("<i", len(p) + 1) + enc
    f = tmp_path / "$IEVIL01.msi"
    f.write_bytes(buf)
    assert RecycleBinPlugin.can_handle(f, "application/octet-stream")
    ev = list(RecycleBinPlugin(_ctx(f)).parse())
    assert len(ev) == 1
    assert ev[0]["artifact_type"] == "recyclebin"
    assert ev[0]["recyclebin"]["original_path"] == p
    assert ev[0]["recyclebin"]["deleted_time"] == "2026-07-01T11:51:07Z"
    assert ev[0]["timestamp"].endswith("Z")


# ── Windows Timeline ActivitiesCache.db ─────────────────────────────────────────
def test_win_timeline(tmp_path):
    from babel.win_timeline.win_timeline_plugin import WinTimelinePlugin
    f = tmp_path / "ActivitiesCache.db"
    con = sqlite3.connect(f)
    con.execute("CREATE TABLE Activity(AppId,ActivityType,StartTime,EndTime,LastModifiedTime,Payload)")
    con.execute("INSERT INTO Activity VALUES(?,?,?,?,?,?)",
                (json.dumps([{"application": r"C:\Program Files\Google\Chrome\chrome.exe"}]),
                 5, 1782000667, 1782000700, 1782000700, json.dumps({"displayText": "miniwakaya.xyz"})))
    con.commit(); con.close()
    assert WinTimelinePlugin.can_handle(f, "application/octet-stream")
    ev = list(WinTimelinePlugin(_ctx(f)).parse())
    assert len(ev) == 1
    assert ev[0]["artifact_type"] == "timeline_activity"
    assert ev[0]["process"]["name"] == "chrome.exe"
    assert ev[0]["timestamp"].endswith("Z")


# ── Notifications wpndatabase.db ─────────────────────────────────────────────────
def test_notifications(tmp_path):
    from babel.notifications.notifications_plugin import NotificationsPlugin
    f = tmp_path / "wpndatabase.db"
    con = sqlite3.connect(f)
    con.execute("CREATE TABLE NotificationHandler(RecordId,PrimaryId)")
    con.execute("CREATE TABLE Notification(HandlerId,Type,Payload,ArrivalTime,ExpiryTime)")
    con.execute("INSERT INTO NotificationHandler VALUES(1,?)", ("Microsoft.Teams",))
    con.execute("INSERT INTO Notification VALUES(1,?,?,?,?)",
                ("toast", "<toast><text>New message from Bob</text></toast>", _FT, 0))
    con.commit(); con.close()
    assert NotificationsPlugin.can_handle(f, "application/octet-stream")
    ev = list(NotificationsPlugin(_ctx(f)).parse())
    assert len(ev) == 1
    assert ev[0]["artifact_type"] == "notifications"
    assert ev[0]["notification"]["app"] == "Microsoft.Teams"
    assert "Bob" in ev[0]["notification"]["text"]


# ── Mark-of-the-Web (Zone.Identifier) ────────────────────────────────────────────
def test_markofweb(tmp_path):
    from babel.markofweb.markofweb_plugin import MarkOfWebPlugin
    f = tmp_path / "evil.msi.Zone.Identifier"
    f.write_text("[ZoneTransfer]\nZoneId=3\nReferrerUrl=https://miniwakaya.xyz/\n"
                 "HostUrl=https://miniwakaya.xyz/Bin/ScreenConnect.ClientSetup.msi\n")
    assert MarkOfWebPlugin.can_handle(f, "text/plain")
    ev = list(MarkOfWebPlugin(_ctx(f)).parse())
    assert len(ev) == 1
    assert ev[0]["artifact_type"] == "mark_of_web"
    assert ev[0]["url"]["domain"] == "miniwakaya.xyz"
    assert ev[0]["mark_of_web"]["zone"] == "Internet"


# ── Trend Micro telemetry ────────────────────────────────────────────────────────
def test_trend_telemetry(tmp_path):
    from babel.trend_telemetry.trend_telemetry_plugin import TrendTelemetryPlugin
    rec = {
        "eventSourceType": "1", "eventSubId": "603", "endpointGuid": "x",
        "endpointHostName": "ILD-PF43X2N8", "endpointIp": ["10.49.124.215"],
        "logonUser": "aflohic", "userDomain": "ILIAD",
        "processName": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "processFileHashSha256": "2397c84d", "processPid": "19844",
        "request": "https://miniwakaya.xyz/Bin/ScreenConnect.ClientSetup.msi",
        "objectHostName": "miniwakaya.xyz", "filterRiskLevel": "high",
        "tags": ["MITRE.T1566 - Phishing", "MITRE.T1219 - Remote Access Software"],
        "firstSeen": "2026-07-01T11:51:07Z", "osName": "Windows",
    }
    f = tmp_path / "trend.json"
    f.write_text(json.dumps([rec]))
    assert TrendTelemetryPlugin.can_handle(f, "application/json")
    ev = list(TrendTelemetryPlugin(_ctx(f)).parse())
    assert len(ev) == 1
    e = ev[0]
    assert e["artifact_type"] == "trend_telemetry"
    assert e["process"]["name"] == "chrome.exe"
    assert e["process"]["hash"]["sha256"] == "2397c84d"
    assert e["host"]["hostname"] == "ILD-PF43X2N8"
    assert e["url"]["domain"] == "miniwakaya.xyz"
    assert set(e["mitre"]["id"]) == {"T1566", "T1219"}
    assert e["level"] == "high"


# ── Registry decoders: UserAssist + BAM ──────────────────────────────────────────
def test_registry_userassist_and_bam():
    from babel.registry.registry_plugin import RegistryPlugin
    inst = RegistryPlugin.__new__(RegistryPlugin)

    ua = bytearray(72)
    struct.pack_into("<I", ua, 4, 7)          # run count
    struct.pack_into("<Q", ua, 60, _FT)       # last-exec FILETIME
    name = codecs.encode(r"C:\Windows\System32\cmd.exe", "rot_13")
    vals = {name: {"data_b64": base64.b64encode(bytes(ua)).decode()}}
    ua_ev = list(inst._decode_special(
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{G}\Count", vals, ""))
    assert ua_ev and ua_ev[0]["artifact_type"] == "userassist"
    assert ua_ev[0]["userassist"]["run_count"] == 7
    assert ua_ev[0]["process"]["name"] == "cmd.exe"

    bam = bytearray(24)
    struct.pack_into("<Q", bam, 0, _FT)
    vals2 = {r"\Device\HarddiskVolume3\Windows\System32\powershell.exe":
             {"data_b64": base64.b64encode(bytes(bam)).decode()}}
    bam_ev = list(inst._decode_special(
        r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1", vals2, ""))
    assert bam_ev and bam_ev[0]["artifact_type"] == "bam"
    assert bam_ev[0]["bam"]["last_executed"] == "2026-07-01T11:51:07Z"


# ── Jump List (only if olefile present) ──────────────────────────────────────────
def test_jumplist_can_handle(tmp_path):
    from babel.jumplist.jumplist_plugin import JumpListPlugin
    f = tmp_path / "5f7b5f1e01b83767.automaticDestinations-ms"
    f.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32)  # OLE magic
    assert JumpListPlugin.can_handle(f, "application/octet-stream")
