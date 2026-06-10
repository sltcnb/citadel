"""
Antivirus / EDR plugin — vendor detection logs, quarantine metadata, scan logs.

The collector gathers AV/EDR artifacts under  antivirus/<vendor>/...  for ~16
Windows vendors (Defender, Trend Micro, Symantec, McAfee/Trellix, Sophos, ESET,
Kaspersky, Bitdefender, CrowdStrike, SentinelOne, Carbon Black, ...) and a
handful of Linux ones (ClamAV, mdatp, ds_agent, falcon, sophos-spl, rkhunter).

These are heterogeneous: mostly text logs (one event per line) but some binary
(Defender DetectionHistory / Quarantine blobs). This plugin types everything as
`antivirus` so detections are searchable and filterable in one place:
  - text  → one event per non-blank line, light timestamp extraction
  - binary→ a single "collected" event so the artifact still appears + is found

The vendor is taken from the archive path (antivirus/<vendor>/...). Pure stdlib.
"""

from __future__ import annotations

import re
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

MAX_LINES = 20_000  # cap events per file
MAX_MSG = 1_000  # truncate very long log lines
_PROBE = 8192  # bytes sampled for the text/binary heuristic

# Filenames that identify AV logs even without the antivirus/ path context.
_HANDLED = {
    "MPLOG.LOG",
    "MPCMDRUN.LOG",
    "MPDETECTION.LOG",
    "CLAMAV.LOG",
    "FRESHCLAM.LOG",
    "RKHUNTER.LOG",
}

# Leading-timestamp patterns commonly seen in AV logs.
_TS_PATTERNS = [
    (re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})"), "%Y-%m-%d %H:%M:%S"),
    (re.compile(r"(\d{2}/\d{2}/\d{4})\s+(\d{2}:\d{2}:\d{2})"), "%m/%d/%Y %H:%M:%S"),
    (re.compile(r"(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})"), "%Y/%m/%d %H:%M:%S"),
]


def _extract_ts(line: str) -> str:
    for rx, fmt in _TS_PATTERNS:
        m = rx.search(line)
        if m:
            try:
                dt = datetime.strptime(f"{m.group(1)} {m.group(2)}", fmt)
                return dt.replace(tzinfo=UTC).isoformat()
            except ValueError:
                continue
    return ""


def _vendor_from_path(fp: Path) -> str:
    parts = [p.lower() for p in fp.parts]
    if "antivirus" in parts:
        i = parts.index("antivirus")
        if i + 1 < len(parts):
            return fp.parts[i + 1]
    return "unknown"


class AntivirusPlugin(BasePlugin):
    PLUGIN_NAME = "antivirus"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "antivirus"
    SUPPORTED_EXTENSIONS = []
    SUPPORTED_MIME_TYPES = ["text/x-antivirus"]
    PLUGIN_PRIORITY = 105  # beat syslog (50) for files under antivirus/

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(_HANDLED)

    def _looks_binary(self, sample: bytes) -> bool:
        if b"\x00" in sample:
            return True
        if not sample:
            return False
        text = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
        return (text / len(sample)) < 0.70

    def _mtime(self, fp: Path) -> str:
        try:
            return datetime.fromtimestamp(fp.stat().st_mtime, tz=UTC).isoformat()
        except OSError:
            return datetime.now(UTC).isoformat()

    def parse(self) -> Generator[dict[str, Any], None, None]:
        fp = self.ctx.source_file_path
        vendor = _vendor_from_path(fp)
        mtime = self._mtime(fp)

        try:
            with open(fp, "rb") as fh:
                sample = fh.read(_PROBE)
        except Exception as exc:
            raise PluginFatalError(f"Cannot read antivirus file: {exc}")

        # ── Binary artifact (quarantine blob, DetectionHistory) ──────────────
        if self._looks_binary(sample):
            try:
                size = fp.stat().st_size
            except OSError:
                size = len(sample)
            yield self.make_event(
                timestamp=mtime,
                timestamp_desc="File mtime",
                message=f"[{vendor}] collected AV artifact: {fp.name} ({size:,} bytes)",
                artifact_type="antivirus",
                raw={"vendor": vendor, "file": fp.name, "size_bytes": size, "binary": True},
                antivirus={"vendor": vendor, "file": fp.name, "size_bytes": size, "binary": True},
            )
            self._count = 1
            return

        # ── Text log (one event per non-blank line) ──────────────────────────
        count = 0
        try:
            with open(fp, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if count >= MAX_LINES:
                        break
                    line = line.rstrip("\r\n")
                    if not line.strip():
                        continue
                    ts = _extract_ts(line) or mtime
                    msg = line if len(line) <= MAX_MSG else line[:MAX_MSG] + "…"
                    yield self.make_event(
                        timestamp=ts,
                        timestamp_desc="Log entry" if _extract_ts(line) else "File mtime",
                        message=f"[{vendor}] {msg}",
                        artifact_type="antivirus",
                        raw={"vendor": vendor, "file": fp.name, "line": line},
                        antivirus={"vendor": vendor, "file": fp.name},
                    )
                    count += 1
        except Exception as exc:
            raise PluginFatalError(f"Antivirus log read failed: {exc}")
        self._count = count

    def get_stats(self) -> dict[str, Any]:
        return {"events": getattr(self, "_count", 0)}
