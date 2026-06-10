"""
Windows Error Reporting (WER) plugin — parses .wer crash report files
collected by fo-harvester's 'wer_crashes' artifact category.

.wer files are UTF-16 XML structured as:
    <?xml version="1.0" encoding="UTF-16"?>
    <WERReportMetadata>
      <WERSystemMetadata>...</WERSystemMetadata>
      <WERProcessInformation>
        <AppName>chrome.exe</AppName>
        <AppPath>C:\\Program Files\\Google\\Chrome\\...</AppPath>
        ...
      </WERProcessInformation>
      <WERReportInformation>
        <FriendlyEventName>Stopped working</FriendlyEventName>
        <EventTime>133570000000000000</EventTime>   <!-- FILETIME 100-ns ticks -->
        ...
      </WERReportInformation>
    </WERReportMetadata>

Routing: utils/file_type.py maps .wer → 'application/x-windows-wer'.

Priority 100 — wins over strings fallback (1).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

# FILETIME epoch: 1601-01-01T00:00:00Z
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_100NS_PER_SEC = 10_000_000


def _filetime_to_iso(ft_str: str) -> str:
    """Convert a Windows FILETIME (100-ns ticks since 1601) to ISO-8601 UTC string."""
    try:
        ticks = int(ft_str)
        dt = _FILETIME_EPOCH + timedelta(seconds=ticks / _100NS_PER_SEC)
        return dt.isoformat()
    except (ValueError, TypeError, OverflowError):
        return ""


def _text(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


class WerPlugin(BasePlugin):
    PLUGIN_NAME = "wer"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "process"
    PLUGIN_PRIORITY = 100
    SUPPORTED_MIME_TYPES = ["application/x-windows-wer"]
    SUPPORTED_EXTENSIONS = [".wer"]

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            raw_bytes = path.read_bytes()
            if raw_bytes[:2] in (b"\xff\xfe", b"\xfe\xff"):
                text = raw_bytes.decode("utf-16")
            else:
                text = raw_bytes.decode("utf-8", errors="replace")
            root = ET.fromstring(text)
        except Exception as exc:
            raise PluginFatalError(f"Cannot parse WER file '{path.name}': {exc}") from exc

        # ── System metadata ───────────────────────────────────────────────────
        sys_meta = root.find("WERSystemMetadata")
        machine = _text(sys_meta.find("MachineName")) if sys_meta is not None else ""
        os_ver = _text(sys_meta.find("OSVersion")) if sys_meta is not None else ""

        # ── Process information ────────────────────────────────────────────────
        proc_info = root.find("WERProcessInformation")
        app_name = ""
        app_path = ""
        pid = ""
        if proc_info is not None:
            app_name = _text(proc_info.find("AppName"))
            app_path = _text(proc_info.find("AppPath"))
            pid = _text(proc_info.find("ProcessId"))

        # ── Report information ─────────────────────────────────────────────────
        report_info = root.find("WERReportInformation")
        event_name = ""
        friendly_name = ""
        event_time_str = ""
        report_id = ""
        if report_info is not None:
            event_name = _text(report_info.find("EventName"))
            friendly_name = _text(report_info.find("FriendlyEventName"))
            event_time_str = _text(report_info.find("EventTime"))
            report_id = _text(report_info.find("ReportIdentifier"))

        timestamp = _filetime_to_iso(event_time_str)
        if not timestamp:
            timestamp = datetime.now(UTC).isoformat()

        display_name = app_name or path.stem
        description = friendly_name or event_name or "Application crash"
        message = f"WER Crash: {display_name} — {description}"
        if machine:
            message += f" (host: {machine})"

        yield {
            "timestamp": timestamp,
            "timestamp_desc": "WER EventTime",
            "message": message,
            "artifact_type": "process",
            "host": {
                "hostname": machine,
                "os": os_ver,
            },
            "process": {
                "name": app_name,
                "path": app_path,
                "pid": int(pid) if pid.isdigit() else 0,
            },
            "raw": {
                "app_name": app_name,
                "app_path": app_path,
                "event_name": event_name,
                "friendly_name": friendly_name,
                "report_id": report_id,
                "os_version": os_ver,
                "machine_name": machine,
            },
        }
