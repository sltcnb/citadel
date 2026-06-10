"""
JSON file plugin — indexes structured config files as searchable events and
emits metadata-only events for opaque text blobs.

Artifact types:
  json      — .json (one event per top-level element / single dict)
  yaml      — .yaml/.yml (one event per top-level key)
  csv_row   — .csv (one event per row, up to MAX_CSV_ROWS)
  file      — .txt/.log/.conf/.cfg/.ini/.toml/.xml/.ps1/.sh/.bat/.py
              ONE event carrying file metadata (size, mtime, sha256, line_count).
              The full text content is NOT chunked into multiple events any more;
              if you need full content, the file lives in MinIO as the source artifact.

Priority 15 — fallback for readable structured files not claimed by specific
parsers (e.g. hayabusa, ndjson, plaso).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError


def _file_mtime_iso(p: Path) -> str:
    try:
        return datetime.fromtimestamp(p.stat().st_mtime, tz=UTC).isoformat()
    except OSError:
        return datetime.now(UTC).isoformat()


# Max bytes we'll read to compute a preview / line count
MAX_BYTES = 5 * 1024 * 1024
# Max CSV rows
MAX_CSV_ROWS = 5000
# Extensions treated as opaque text (file-metadata only)
_OPAQUE_EXTS = {
    ".txt",
    ".log",
    ".conf",
    ".cfg",
    ".ini",
    ".toml",
    ".xml",
    ".ps1",
    ".psm1",
    ".sh",
    ".bat",
    ".cmd",
    ".py",
}


def _try_yaml(text: str) -> Any:
    try:
        import yaml

        return yaml.safe_load(text)
    except Exception:
        return None


class JsonFilePlugin(BasePlugin):
    PLUGIN_NAME = "json_file"
    PLUGIN_VERSION = "2.0.0"
    DEFAULT_ARTIFACT_TYPE = "file"
    SUPPORTED_EXTENSIONS = [
        ".json",
        ".yaml",
        ".yml",
        ".txt",
        ".log",
        ".conf",
        ".cfg",
        ".ini",
        ".toml",
        ".xml",
        ".csv",
        ".ps1",
        ".psm1",
        ".sh",
        ".bat",
        ".cmd",
        ".py",
    ]
    SUPPORTED_MIME_TYPES = [
        "text/plain",
        "text/html",
        "text/xml",
        "text/csv",
        "application/json",
        "application/yaml",
    ]
    PLUGIN_PRIORITY = 15

    def parse(self) -> Generator[dict[str, Any], None, None]:
        fp = self.ctx.source_file_path
        ext = fp.suffix.lower()
        filename = fp.name
        self._mtime = _file_mtime_iso(fp)
        self._fp = fp

        try:
            raw = fp.read_bytes()
        except Exception as exc:
            raise PluginFatalError(f"Cannot read file: {exc}")

        size_bytes = fp.stat().st_size if fp.exists() else len(raw)
        truncated = len(raw) > MAX_BYTES
        if truncated:
            raw = raw[:MAX_BYTES]

        text = raw.decode("utf-8", errors="replace")
        sha256 = hashlib.sha256(raw).hexdigest()
        self._meta = {
            "filename": filename,
            "size_bytes": size_bytes,
            "sha256": sha256,
            "truncated": truncated,
        }

        if ext == ".json" or (not ext and text.lstrip().startswith(("{", "["))):
            yield from self._parse_json(filename, text)
        elif ext in (".yaml", ".yml"):
            yield from self._parse_yaml(filename, text)
        elif ext == ".csv" or (not ext and self._looks_like_csv(text)):
            yield from self._parse_csv(filename, text)
        else:
            # Opaque text — emit metadata-only file event (artifact_type=file).
            yield self._file_metadata_event(text)

    # ── JSON ──────────────────────────────────────────────────────────────────

    def _parse_json(self, filename: str, text: str) -> Generator[dict, None, None]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Not valid JSON → treat as opaque text.
            yield self._file_metadata_event(text)
            return

        if isinstance(data, list):
            for i, item in enumerate(data):
                yield self._structured_event(
                    "json",
                    f"{filename}[{i}]"
                    + (f": {self._preview_str(item)}" if item is not None else ""),
                    item if isinstance(item, dict) else {"value": item, "index": i},
                )
        elif isinstance(data, dict):
            yield self._structured_event(
                "json",
                f"{filename}: {self._preview_str(data)}",
                data,
            )
        else:
            yield self._structured_event(
                "json",
                f"{filename}: {self._preview_str(data)}",
                {"value": data},
            )

    # ── YAML ──────────────────────────────────────────────────────────────────

    def _parse_yaml(self, filename: str, text: str) -> Generator[dict, None, None]:
        data = _try_yaml(text)
        if data is None:
            yield self._file_metadata_event(text)
            return
        if isinstance(data, dict):
            for key, value in data.items():
                yield self._structured_event(
                    "yaml",
                    f"{filename} | {key}: {self._preview_str(value)}",
                    {"key": key, "value": value},
                )
        else:
            yield self._structured_event(
                "yaml",
                f"{filename}: {self._preview_str(data)}",
                {"value": data},
            )

    # ── CSV ───────────────────────────────────────────────────────────────────

    def _parse_csv(self, filename: str, text: str) -> Generator[dict, None, None]:
        reader = csv.DictReader(io.StringIO(text))
        for i, row in enumerate(reader):
            if i >= MAX_CSV_ROWS:
                break
            first_val = next((str(v)[:80] for v in row.values() if v), "")
            yield self._structured_event(
                "csv_row",
                f"{filename}[{i}]: {first_val}",
                dict(row),
            )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _looks_like_csv(self, text: str) -> bool:
        """Return True if content looks like a CSV (consistent comma-delimited rows)."""
        lines = [l for l in text.splitlines()[:6] if l.strip()]
        if len(lines) < 2:
            return False
        if "," not in lines[0]:
            return False
        try:
            reader = csv.reader(lines)
            counts = [len(row) for row in reader]
            return len(counts) >= 2 and counts[0] > 1 and all(c == counts[0] for c in counts)
        except Exception:
            return False

    def _preview_str(self, val: Any) -> str:
        if val is None:
            return "<null>"
        if isinstance(val, (dict, list)):
            return f"<{type(val).__name__} {len(val)} items>"
        s = str(val)
        return s if len(s) <= 80 else s[:80] + "…"

    def _file_metadata_event(self, text: str) -> dict:
        """One event with file-metadata only — no content chunking."""
        line_count = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
        first_line = ""
        if text:
            first_line = text.split("\n", 1)[0].strip()[:120]

        meta = {**self._meta, "line_count": line_count}

        return {
            "timestamp": self._mtime,
            "timestamp_desc": "File mtime",
            "message": (
                f"{meta['filename']}  ({meta['size_bytes']:,} bytes, "
                f"{line_count} lines, sha256={meta['sha256'][:12]}…)"
                + (f"  first: {first_line}" if first_line else "")
            ),
            "artifact_type": "file",
            "file": meta,
            "raw": meta,
        }

    def _structured_event(self, atype: str, message: str, payload: dict) -> dict:
        """Per-record event (json/yaml/csv_row) carrying the full row in raw."""
        return {
            "timestamp": self._mtime,
            "timestamp_desc": "File mtime",
            "message": message,
            "artifact_type": atype,
            atype: payload if isinstance(payload, dict) else {"value": payload},
            "raw": payload if isinstance(payload, dict) else {"value": payload},
        }
