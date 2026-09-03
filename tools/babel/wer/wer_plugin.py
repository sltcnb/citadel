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
from pathlib import Path
from typing import Any

# .wer files arrive through the ingest pipeline, so the XML is untrusted.
# safe_xml refuses entity declarations (billion-laughs / XXE).
from babel.base_plugin import BasePlugin, PluginFatalError
from babel.safe_xml import parse_string as _parse_xml_string

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


# Root elements Windows uses for a WER report. WERReportMetadata is the queued
# .tmp.xml form; the others appear in archived reports across Windows versions.
_WER_ROOTS = frozenset({"werreportmetadata", "wer", "werreport"})


def _is_wer_document(path: Path) -> bool:
    """True if *path* is XML whose root element marks it as a WER report."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = head.decode("utf-16", errors="replace")
    else:
        text = head.decode("utf-8", errors="replace")
    # Match the first element name without a full parse — the head is a prefix,
    # so ET.fromstring would fail on truncation.
    for token in text.split("<"):
        token = token.strip()
        if not token or token.startswith(("?", "!")):
            continue
        return token.split(">")[0].split()[0].strip("/").lower() in _WER_ROOTS
    return False


# Keys that identify the INI-like archived .wer form. Requiring one of these
# (rather than "has an = sign") keeps arbitrary key=value text out.
_WER_INI_KEYS = ("eventtype=", "eventname=", "appname=", "sig[0].name=", "eventtime=")


def _is_wer_ini(path: Path) -> bool:
    """True if *path* is the key=value form Windows writes for archived reports."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = head.decode("utf-16", errors="replace")
    else:
        text = head.decode("utf-8", errors="replace")
    lowered = text.lower()
    return any(key in lowered for key in _WER_INI_KEYS)


def _file_mtime_iso(path: Path) -> str:
    """File mtime as ISO-8601 UTC — the fallback when a report carries no EventTime."""
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()
    except OSError:
        return datetime.now(UTC).isoformat()


class WerPlugin(BasePlugin):
    PLUGIN_NAME = "wer"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "process"
    PLUGIN_PRIORITY = 100
    SUPPORTED_MIME_TYPES = ["application/x-windows-wer"]
    SUPPORTED_EXTENSIONS = [".wer"]

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        """Claim WER reports whatever Windows named them.

        The ``.wer`` extension covers only part of what is actually on disk.
        Windows writes queued reports as ``WER.<guid>.tmp.xml`` (and appraiser
        variants), and Talon collects everything under ReportQueue/ReportArchive
        verbatim — so the common real case was reaching the plist parser (which
        claimed any XML) and being emitted as a single null event instead.

        The name is only a hint; the root element is the decision, so a foreign
        XML file that happens to sit in a WER directory is not claimed.
        """
        if super().can_handle(file_path, mime_type):
            return True
        name = file_path.name.lower()
        in_wer_dir = {p.lower() for p in file_path.parts} & {
            "wer",
            "wer_crashes",
            "reportqueue",
            "reportarchive",
        }
        if not (name.startswith("wer") or name.endswith(".wer") or in_wer_dir):
            return False
        return _is_wer_document(file_path) or _is_wer_ini(file_path)

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            raw_bytes = path.read_bytes()
            if raw_bytes[:2] in (b"\xff\xfe", b"\xfe\xff"):
                text = raw_bytes.decode("utf-16")
            else:
                text = raw_bytes.decode("utf-8", errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot read WER file '{path.name}': {exc}") from exc

        # Archived .wer reports are INI-like key=value, not XML — the plugin
        # advertised ".wer" but only ever parsed XML, so every real archived
        # report raised here and fell through to the strings floor.
        if not text.lstrip().startswith("<"):
            yield from self._parse_ini(path, text)
            return

        try:
            root = _parse_xml_string(text)
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

    # ── Archived .wer reports (INI-like key=value) ────────────────────────────

    def _parse_ini(self, path: Path, text: str) -> Generator[dict[str, Any], None, None]:
        """Parse the key=value form Windows writes for archived reports.

        Same event shape as the XML branch so both forms are indistinguishable
        downstream. The ``Sig[N].Name``/``Sig[N].Value`` pairs are the crash
        bucket parameters — faulting module, offset, exception code — so they are
        folded into a name→value map rather than kept as opaque indices.
        """
        fields: dict[str, str] = {}
        sig_names: dict[str, str] = {}
        sig_values: dict[str, str] = {}

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith((";", "#", "[")) or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if key.startswith("Sig[") and key.endswith("].Name"):
                sig_names[key[4:-6]] = value
            elif key.startswith("Sig[") and key.endswith("].Value"):
                sig_values[key[4:-7]] = value
            else:
                fields[key] = value

        signature = {
            sig_names[idx]: sig_values.get(idx, "") for idx in sorted(sig_names) if sig_names[idx]
        }

        app_name = fields.get("AppName", "") or signature.get("Application Name", "")
        app_path = fields.get("AppPath", "")
        event_name = fields.get("EventType", "") or fields.get("EventName", "")
        machine = fields.get("MachineName", "")
        os_ver = fields.get("OSVersion", "")
        pid = fields.get("TargetAppId", "") or fields.get("ProcessId", "")

        timestamp = _filetime_to_iso(fields.get("EventTime", ""))
        if not timestamp:
            timestamp = _file_mtime_iso(path)

        display_name = app_name or path.stem
        message = f"WER Crash: {display_name} — {event_name or 'Application crash'}"
        if machine:
            message += f" (host: {machine})"

        yield {
            "timestamp": timestamp,
            "timestamp_desc": "WER EventTime",
            "message": message,
            "artifact_type": "process",
            "host": {"hostname": machine, "os": os_ver},
            "process": {
                "name": app_name,
                "path": app_path,
                "pid": int(pid) if pid.isdigit() else 0,
            },
            "raw": {
                "app_name": app_name,
                "app_path": app_path,
                "event_name": event_name,
                "report_id": fields.get("ReportIdentifier", ""),
                "os_version": os_ver,
                "machine_name": machine,
                "signature": signature,
                "fields": fields,
                "format": "ini",
            },
        }
