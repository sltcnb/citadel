"""
NDJSON Plugin — generic JSON Lines / NDJSON parser.

Accepts .jsonl, .ndjson, or .json files where each line is a valid JSON object.
Attempts to auto-detect timestamp and message fields from common naming conventions.

No extra dependencies required (Python stdlib only).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

# Timestamp field candidates (tried in order)
_TS_FIELDS = [
    "@timestamp",
    "timestamp",
    "ts",
    "time",
    "datetime",
    "created_at",
    "createdAt",
    "event_time",
    "eventTime",
    "date",
    "time_local",
    "log_date",
    "occurred",
]

# Message field candidates (tried in order)
_MSG_FIELDS = [
    "message",
    "msg",
    "description",
    "text",
    "log",
    "event",
    "raw",
    "details",
    "summary",
    "content",
    "body",
    "data",
    "entry",
]

# Hostname/source field candidates
_HOST_FIELDS = [
    "hostname",
    "host",
    "computer_name",
    "computerName",
    "source",
    "agent",
    "device",
    "node",
    "fqdn",
    "source_host",
    "sourceHost",
]

# How many lines to scan for auto-detection
_DETECT_LINES = 5


def _first_nonempty(obj: dict, keys: list[str]) -> str:
    for k in keys:
        v = obj.get(k)
        if v and isinstance(v, str):
            return v
        if v and not isinstance(v, (dict, list)):
            return str(v)
    return ""


def _looks_like_jsonl(path: Path) -> bool:
    """Detect if a .json file is actually JSON Lines (not a single JSON object/array)."""
    try:
        with open(path, errors="replace") as fh:
            valid = 0
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        valid += 1
                except (json.JSONDecodeError, ValueError):
                    return False
                if valid >= _DETECT_LINES:
                    break
            return valid >= 2
    except OSError:
        return False


class NdjsonPlugin(BasePlugin):
    """Parses generic JSON Lines / NDJSON files."""

    PLUGIN_NAME = "ndjson"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "ndjson"
    SUPPORTED_EXTENSIONS = [".jsonl", ".ndjson"]
    SUPPORTED_MIME_TYPES = [
        "application/x-ndjson",
        "application/jsonl",
        "application/ndjson",
        "text/plain",
    ]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._parsed = 0
        self._skipped = 0

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        ext = file_path.suffix.lower()
        if ext in (".jsonl", ".ndjson"):
            return True
        # Also accept plain .json files that look like JSON Lines
        if ext == ".json":
            return _looks_like_jsonl(file_path)
        return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open NDJSON file: {exc}") from exc

        with fh:
            for lineno, raw_line in enumerate(fh, 1):
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    obj = json.loads(raw_line)
                except (json.JSONDecodeError, ValueError):
                    self._skipped += 1
                    continue

                if not isinstance(obj, dict):
                    self._skipped += 1
                    continue

                ts = _first_nonempty(obj, _TS_FIELDS)
                msg = _first_nonempty(obj, _MSG_FIELDS)
                host = _first_nonempty(obj, _HOST_FIELDS)

                # If no message field found, build one from key=value pairs
                if not msg:
                    parts = []
                    for k, v in list(obj.items())[:6]:
                        if k in _TS_FIELDS or k in _HOST_FIELDS:
                            continue
                        if isinstance(v, (str, int, float, bool)):
                            parts.append(f"{k}={v}")
                    msg = "  ".join(parts) or f"Line {lineno}"

                self._parsed += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "ndjson",
                    "timestamp": ts,
                    "timestamp_desc": "Event Time",
                    "message": msg[:512],  # cap length
                    "host": {"hostname": host},
                    "ndjson": {k: v for k, v in obj.items() if k not in ("raw",)},
                    "raw": obj,
                }

    def get_stats(self) -> dict[str, Any]:
        return {"records_parsed": self._parsed, "records_skipped": self._skipped}
