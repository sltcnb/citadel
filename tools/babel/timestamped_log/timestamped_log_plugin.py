"""Generic timestamped-line log parser.

Catches the long tail of application logs that aren't syslog and aren't JSON —
ClickHouse, database engines, app servers, build/tooling output — anything whose
lines begin with a recognizable timestamp. Each line becomes a timeline event
with an extracted timestamp + severity; continuation lines (stack traces, SQL
bodies) fold into the preceding event so a traceback stays one row.

Sits below dedicated parsers (syslog, evtx, …) and above the json_file/strings
catch-alls, so structured logs still win but a plain app log becomes real events
instead of a single "file" metadata blob. Transparently reads .gz.
"""
from __future__ import annotations

import re
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError, iso_z

# Leading-timestamp matchers, tried in order. Each returns (iso_ts, msg_start).
# A normalizer turns a vendor format into something iso_z can canonicalize.
_ISO = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:[+-]\d{2}:?\d{2}|Z)?"
_CLICKHOUSE = r"\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?"  # 2026.04.06 18:36:43.529137
_SYSLOG3164 = r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"  # Jan  1 12:34:56

_MATCHERS = [
    (re.compile(rf"^\[?({_ISO})\]?\s+"), lambda s: s.replace(",", ".")),
    (re.compile(rf"^({_CLICKHOUSE})\s+"), lambda s: s.replace(".", "-", 2).replace(" ", "T")),
]
# Bare-timestamp probe used only for can_handle sniffing (incl. syslog form).
_ANY_TS = re.compile(rf"^\[?(?:{_ISO}|{_CLICKHOUSE}|{_SYSLOG3164})\]?\b")

_LEVEL = re.compile(
    r"<(Trace|Debug|Information|Notice|Warning|Error|Fatal)>"  # ClickHouse <Level>
    r"|\b(TRACE|DEBUG|INFO|INFORMATION|NOTICE|WARN|WARNING|ERROR|ERR|CRITICAL|CRIT|FATAL|ALERT|EMERG)\b"
)

_MAX_LINES = 300_000       # hard cap so a multi-GB log can't run unbounded
_MAX_MSG = 2000            # cap a single (folded) message length
_SNIFF_LINES = 40          # how many lines can_handle inspects
_SNIFF_MIN_RATIO = 0.6     # fraction that must be timestamped to claim the file


def _open_text(path: Path):
    if path.name.lower().endswith(".gz"):
        import gzip

        return gzip.open(path, "rt", errors="replace")
    return open(path, errors="replace")


def _extract(line: str):
    """Return (iso_ts, message) if the line starts with a known timestamp, else None."""
    for rx, norm in _MATCHERS:
        m = rx.match(line)
        if m:
            ts = iso_z(norm(m.group(1)))
            return ts, line[m.end():].strip() or line.strip()
    return None


def _level_of(text: str) -> str:
    m = _LEVEL.search(text)
    if not m:
        return ""
    return (m.group(1) or m.group(2) or "").upper()


class TimestampedLogPlugin(BasePlugin):
    """Per-line parser for application logs with a leading timestamp."""

    PLUGIN_NAME = "timestamped_log"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "log_file"
    SUPPORTED_EXTENSIONS = [".log", ".txt", ".out", ".err"]
    SUPPORTED_MIME_TYPES = ["text/plain", "text/x-log"]
    # Above json_file (15) / strings (1), below syslog (100) and dedicated parsers.
    PLUGIN_PRIORITY = 20

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._parsed = 0
        self._truncated = False

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        try:
            with _open_text(file_path) as fh:
                seen = matched = 0
                for line in fh:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    if seen == 0 and s[:1] in "{[":
                        return False  # JSON/array → json_file/ndjson territory
                    seen += 1
                    if _ANY_TS.match(s):
                        matched += 1
                    if seen >= _SNIFF_LINES:
                        break
                return seen >= 3 and (matched / seen) >= _SNIFF_MIN_RATIO
        except OSError:
            return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            fh = _open_text(path)
        except OSError as exc:
            raise PluginFatalError(f"Cannot open log file: {exc}") from exc

        pending: dict | None = None
        lines_read = 0
        with fh:
            for raw in fh:
                if lines_read >= _MAX_LINES:
                    self._truncated = True
                    break
                lines_read += 1
                line = raw.rstrip("\n")
                if not line.strip():
                    continue
                ext = _extract(line)
                if ext is None:
                    # Continuation (stack trace / SQL body) → fold into prior event.
                    if pending is not None and len(pending["message"]) < _MAX_MSG:
                        pending["message"] = (pending["message"] + " ⏎ " + line.strip())[:_MAX_MSG]
                        pending["log_file"]["lines"] += 1
                    continue
                if pending is not None:
                    self._parsed += 1
                    yield pending
                ts, msg = ext
                lvl = _level_of(line[:120])
                pending = {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "log_file",
                    "timestamp": ts,
                    "timestamp_desc": "Log Time",
                    "message": (msg or line.strip())[:_MAX_MSG],
                    "log_file": {
                        "filename": path.name,
                        "level": lvl,
                        "lines": 1,
                    },
                    "raw": {"line": line[:_MAX_MSG]},
                }
            if pending is not None:
                self._parsed += 1
                yield pending

        if self._truncated:
            yield {
                "fo_id": str(uuid.uuid4()),
                "artifact_type": "log_file",
                "timestamp": None,
                "timestamp_desc": "Note",
                "message": f"⚠ {path.name}: parsing capped at {_MAX_LINES:,} lines (file larger).",
                "log_file": {"filename": path.name, "level": "WARNING", "truncated": True},
                "raw": {},
            }

    def get_stats(self) -> dict[str, Any]:
        return {"records_parsed": self._parsed, "truncated": self._truncated}
