"""
macOS Unified Logging System (ULS) Plugin.

Handles log exports produced by the macOS `log` command:

  Text format (log show / log collect --output):
      2024-01-15 10:30:00.123456-0700  hostname  kernel[0] <Notice>: message
      2024-01-15 10:30:00.123456-0700  hostname  com.apple.security (libsystem_kernel): msg

  JSON/NDJSON format (log show --style json):
      {"timestamp":"2024-01-15 10:30:00.123456-0700","messageType":"Default",
       "processID":456,"subsystem":"com.apple.security","category":"xpc","eventMessage":"..."}

  Log Archive format produced by `log collect`:
    .logarchive directories are not directly parseable without the `log` binary;
    operators should first export them to text/json using:
      log show /path/to/file.logarchive --style json > unified.ndjson

Recognized filenames: *.logarchive (reported as unsupported with guidance),
  unified.log, unified.ndjson, macos_unified.log, system.log (macOS variant).

No extra dependencies required (Python stdlib only).
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

# ── Regex patterns ─────────────────────────────────────────────────────────────

# Text export: "2024-01-15 10:30:00.123456-0700  hostname  process[pid] <Level>: message"
_TEXT_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+[+-]\d{4})"  # timestamp with tz
    r"\s{2,}"  # separator (2+ spaces)
    r"(\S+)"  # hostname
    r"\s{2,}"  # separator
    r"([\w.\-\/]+(?:\[(\d+)\])?)"  # process[pid]
    r"(?:\s+<(\w+)>)?"  # <Level> (optional)
    r":\s+(.*)"  # message
)

# Simplified text format without hostname column
_TEXT_SIMPLE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+[+-]\d{4})"
    r"\s+"
    r"([\w.\-\/]+(?:\[(\d+)\])?)"
    r"(?:\s+<(\w+)>)?"
    r":\s+(.*)"
)

_KNOWN_NAMES = frozenset(
    {
        "unified.log",
        "unified.ndjson",
        "macos_unified.log",
        "macos_logs.json",
        "uls_export.log",
        "uls_export.ndjson",
    }
)

_LEVEL_SEVERITY = {
    "fault": "high",
    "error": "medium",
    "notice": "low",
    "info": "informational",
    "debug": "informational",
    "default": "informational",
}


def _parse_uls_ts(ts_str: str) -> str:
    """
    Convert '2024-01-15 10:30:00.123456-0700' to ISO 8601 UTC.
    Returns empty string on failure.
    """
    try:
        # Normalise: replace space with T
        s = ts_str.replace(" ", "T", 1)
        # Handle +HHMM / -HHMM offset without colon (Python %z needs colon in 3.6)
        # Split at the tz sign
        for sign in ("+", "-"):
            idx = s.rfind(sign)
            if idx > 10:  # not in the date part
                dt_part = s[:idx]
                tz_raw = s[idx:]
                tz_h = int(tz_raw[1:3])
                tz_m = int(tz_raw[3:5]) if len(tz_raw) >= 5 else 0
                tz_sign = 1 if sign == "+" else -1
                offset = timezone(timedelta(hours=tz_sign * tz_h, minutes=tz_sign * tz_m))
                # Parse microseconds
                if "." in dt_part:
                    fmt = "%Y-%m-%dT%H:%M:%S.%f"
                else:
                    fmt = "%Y-%m-%dT%H:%M:%S"
                dt = datetime.strptime(dt_part, fmt).replace(tzinfo=offset)
                return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        return ""
    except Exception:
        return ""


def _parse_json_ts(ts_str: str) -> str:
    """Parse macOS ULS JSON timestamp '2024-01-15 10:30:00.123456-0700'."""
    return _parse_uls_ts(ts_str)


class MacOSULSPlugin(BasePlugin):
    """Parses macOS Unified Logging System exports (text and JSON/NDJSON)."""

    PLUGIN_NAME = "macos_uls"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "macos_uls"
    SUPPORTED_EXTENSIONS = [".log", ".ndjson", ".json"]
    SUPPORTED_MIME_TYPES = ["text/plain", "application/json", "application/x-ndjson"]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._parsed = 0
        self._skipped = 0
        self._mode: str = "unknown"

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(_KNOWN_NAMES)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        name = file_path.name.lower()
        if name in _KNOWN_NAMES:
            return True
        # Peek at first lines
        try:
            with open(file_path, errors="replace") as fh:
                for _ in range(5):
                    line = fh.readline()
                    if not line:
                        break
                    stripped = line.strip()
                    # JSON object with ULS keys
                    if stripped.startswith("{"):
                        try:
                            obj = json.loads(stripped)
                            if "eventMessage" in obj or "messageType" in obj:
                                return True
                        except (json.JSONDecodeError, ValueError):
                            pass
                    # Text pattern
                    if _TEXT_RE.match(line) or _TEXT_SIMPLE_RE.match(line):
                        return True
        except OSError:
            pass
        return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path

        # Detect mode from first non-empty line
        self._mode = self._detect_mode(path)

        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open ULS export: {exc}") from exc

        with fh:
            if self._mode == "json":
                # Single JSON array
                try:
                    data = json.load(fh)
                    if isinstance(data, list):
                        for obj in data:
                            ev = self._parse_json_obj(obj)
                            if ev:
                                self._parsed += 1
                                yield ev
                            else:
                                self._skipped += 1
                except (json.JSONDecodeError, ValueError):
                    self._skipped += 1
            else:
                for raw_line in fh:
                    raw_line = raw_line.rstrip("\n")
                    if not raw_line.strip():
                        continue
                    if self._mode == "ndjson":
                        ev = self._parse_ndjson_line(raw_line)
                    else:
                        ev = self._parse_text_line(raw_line)
                    if ev:
                        self._parsed += 1
                        yield ev
                    else:
                        self._skipped += 1

    def _detect_mode(self, path: Path) -> str:
        try:
            with open(path, errors="replace") as fh:
                for line in fh:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if stripped.startswith("["):
                        return "json"
                    if stripped.startswith("{"):
                        return "ndjson"
                    return "text"
        except OSError:
            pass
        return "text"

    # ── Text format ────────────────────────────────────────────────────────────

    def _parse_text_line(self, line: str) -> dict | None:
        m = _TEXT_RE.match(line)
        if not m:
            m = _TEXT_SIMPLE_RE.match(line)
            if not m:
                return None
            ts_str, proc_raw, pid, level, msg = m.groups()
            hostname = ""
        else:
            ts_str, hostname, proc_raw, pid, level, msg = m.groups()

        ts = _parse_uls_ts(ts_str)
        level = (level or "default").lower()
        severity = _LEVEL_SEVERITY.get(level, "informational")
        proc_name = proc_raw.split("[")[0] if "[" in proc_raw else proc_raw

        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": "macos_uls",
            "timestamp": ts,
            "timestamp_desc": "Log Time",
            "message": f"[{proc_name}] {msg}",
            "host": {"hostname": hostname},
            "process": {"name": proc_name, "pid": pid or ""},
            "macos_uls": {
                "level": level,
                "severity": severity,
                "subsystem": "",
                "category": "",
                "raw_message": msg,
            },
            "raw": {"line": line},
        }

    # ── NDJSON / JSON formats ──────────────────────────────────────────────────

    def _parse_ndjson_line(self, line: str) -> dict | None:
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None
        return self._parse_json_obj(obj)

    def _parse_json_obj(self, obj: dict) -> dict | None:
        if not isinstance(obj, dict):
            return None

        ts_raw = obj.get("timestamp", "")
        ts = _parse_json_ts(ts_raw) if ts_raw else ""
        msg = obj.get("eventMessage", obj.get("message", ""))
        level = (obj.get("messageType", obj.get("type", "default"))).lower()
        severity = _LEVEL_SEVERITY.get(level, "informational")
        proc_name = obj.get("processImageShortName", obj.get("process", ""))
        pid = str(obj.get("processID", ""))
        subsystem = obj.get("subsystem", "")
        category = obj.get("category", "")
        hostname = obj.get("machineID", obj.get("hostname", ""))

        display_msg = f"[{proc_name}] {msg}" if proc_name else msg
        if subsystem:
            display_msg = f"[{subsystem}] {display_msg}"

        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": "macos_uls",
            "timestamp": ts,
            "timestamp_desc": "Log Time",
            "message": display_msg,
            "host": {"hostname": hostname},
            "process": {"name": proc_name, "pid": pid},
            "macos_uls": {
                "level": level,
                "severity": severity,
                "subsystem": subsystem,
                "category": category,
                "thread_id": str(obj.get("threadID", "")),
                "raw_message": msg,
            },
            "raw": {"line": ""},  # already parsed from JSON
        }

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_parsed": self._parsed,
            "records_skipped": self._skipped,
            "mode": self._mode,
        }
