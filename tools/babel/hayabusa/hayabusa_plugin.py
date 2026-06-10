"""
Hayabusa Plugin — parses Hayabusa fast forensics tool output files.

Hayabusa (https://github.com/Yamato-Security/hayabusa) is a Windows event log
fast forensics and threat hunting tool. Run it externally and upload the output:

  hayabusa.exe csv-timeline  -d <evtx_dir> -o results.csv
  hayabusa.exe json-timeline -d <evtx_dir> -o results.jsonl --JSONL-output

Both CSV and JSONL output formats are supported. The plugin auto-detects JSONL
by extension (.jsonl) and Hayabusa CSV by sniffing the header row.
"""

from __future__ import annotations

import csv
import json
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError, PluginParseError

# Columns unique to Hayabusa output — used to distinguish from generic CSVs
_HAYABUSA_REQUIRED_COLS = {"RuleTitle", "Level", "EvtxFile"}

LEVEL_INT = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
}


class HayabusaPlugin(BasePlugin):
    PLUGIN_NAME = "hayabusa"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "hayabusa"
    SUPPORTED_EXTENSIONS = [".jsonl", ".csv"]
    SUPPORTED_MIME_TYPES = ["text/plain", "application/json", "text/csv", "application/x-ndjson"]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._parsed = 0
        self._skipped = 0

    # ── Plugin detection ──────────────────────────────────────────────────────

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        ext = file_path.suffix.lower()
        if ext == ".jsonl":
            return True
        if ext == ".csv":
            return cls._is_hayabusa_csv(file_path)
        return False

    @classmethod
    def _is_hayabusa_csv(cls, path: Path) -> bool:
        """Sniff the header row to confirm this is Hayabusa CSV output."""
        try:
            with open(path, encoding="utf-8-sig", errors="replace") as fh:
                header_line = fh.readline().strip()
            cols = {c.strip().strip('"') for c in header_line.split(",")}
            return _HAYABUSA_REQUIRED_COLS.issubset(cols)
        except Exception:
            return False

    # ── Parsing ───────────────────────────────────────────────────────────────

    def parse(self) -> Generator[dict[str, Any], None, None]:
        ext = self.ctx.source_file_path.suffix.lower()
        try:
            if ext == ".jsonl":
                yield from self._parse_jsonl()
            else:
                yield from self._parse_csv()
        except PluginParseError:
            raise
        except PluginFatalError:
            raise
        except Exception as exc:
            raise PluginFatalError(f"Cannot read Hayabusa file: {exc}") from exc

    def _parse_jsonl(self) -> Generator[dict[str, Any], None, None]:
        with open(self.ctx.source_file_path, encoding="utf-8-sig", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    yield self._record_to_event(row, raw_line=line)
                    self._parsed += 1
                except (json.JSONDecodeError, KeyError) as exc:
                    self._skipped += 1
                    self.log.debug("Skipped JSONL line %d: %s", lineno, exc)
                except PluginParseError:
                    self._skipped += 1

    def _parse_csv(self) -> Generator[dict[str, Any], None, None]:
        with open(self.ctx.source_file_path, encoding="utf-8-sig", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for lineno, row in enumerate(reader, 2):
                try:
                    yield self._record_to_event(row, raw_line=json.dumps(dict(row)))
                    self._parsed += 1
                except PluginParseError:
                    self._skipped += 1
                    self.log.debug("Skipped CSV row %d", lineno)

    # ── Record → event ────────────────────────────────────────────────────────

    def _record_to_event(self, row: dict, raw_line: str = "") -> dict[str, Any]:
        timestamp_raw = row.get("Timestamp") or row.get("timestamp") or ""
        rule_title = str(row.get("RuleTitle") or row.get("ruleTitle") or "")
        level = str(row.get("Level") or row.get("level") or "informational").lower()
        computer = str(row.get("Computer") or row.get("computer") or "")
        channel = str(row.get("Channel") or row.get("channel") or "")
        event_id_raw = str(row.get("EventID") or row.get("eventId") or "")
        record_id_raw = str(row.get("RecordID") or row.get("recordId") or "")
        details_raw = str(row.get("Details") or row.get("details") or "")
        extra_field = str(row.get("ExtraFieldInfo") or row.get("extraFieldInfo") or "")
        rule_file = str(row.get("RuleFile") or row.get("ruleFile") or "")
        evtx_file = str(row.get("EvtxFile") or row.get("evtxFile") or "")

        if not rule_title and not timestamp_raw:
            raise PluginParseError("Row missing required fields (RuleTitle/Timestamp)")

        timestamp = self._normalize_timestamp(timestamp_raw)
        level_int = LEVEL_INT.get(level, 1)

        event_id = self._safe_int(event_id_raw)
        record_id = self._safe_int(record_id_raw)

        details_parsed = self._parse_details(details_raw)

        message = f"[{level.upper()}] {rule_title}"
        if computer:
            message += f" on {computer}"

        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": "hayabusa",
            "timestamp": timestamp,
            "timestamp_desc": "Hayabusa Detection Timestamp",
            "message": message,
            "host": {
                "hostname": computer,
            },
            "hayabusa": {
                "rule_title": rule_title,
                "level": level,
                "level_int": level_int,
                "computer": computer,
                "channel": channel,
                "event_id": event_id,
                "record_id": record_id,
                "details_parsed": details_parsed,
                "details_raw": details_raw,
                "rule_file": rule_file,
                "evtx_file": evtx_file,
                "extra_field_info": extra_field,
            },
            "raw": {"line": raw_line} if raw_line else {},
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_timestamp(ts: str) -> str:
        """
        Normalize Hayabusa timestamps to ES-compatible ISO 8601 UTC.

        Hayabusa formats:
          "2023-01-15 14:32:11.234 +00:00"   (space separator, explicit tz)
          "2023-01-15T14:32:11.234+00:00"     (T separator, explicit tz)
          "2023-01-15 14:32:11.234 +09:00"   (JST offset)
        Target: "2023-01-15T14:32:11.234Z"   (T, ms, Z)
        """
        if not ts:
            return ""
        ts = ts.strip()

        # Replace first space (date/time separator) with T, preserving tz spaces
        # Format is "YYYY-MM-DD HH:MM:SS.fff +HH:MM" → split into date+rest
        if len(ts) > 10 and ts[10] == " ":
            ts = ts[:10] + "T" + ts[11:]

        # Remove space before timezone offset: "...111 +00:00" → "...111+00:00"
        ts = ts.replace(" +", "+").replace(" -", "-")

        # Truncate fractional seconds to milliseconds (3 digits)
        dot = ts.find(".")
        if dot != -1:
            end = dot + 1
            while end < len(ts) and ts[end].isdigit():
                end += 1
            suffix = ts[end:]
            frac = (ts[dot + 1 : end] + "000")[:3]
            ts = ts[: dot + 1] + frac + suffix

        # Normalise +00:00 → Z
        if ts.endswith("+00:00"):
            ts = ts[:-6] + "Z"
        elif not (ts.endswith("Z") or "+" in ts[10:] or (len(ts) > 19 and ts[-3] == ":")):
            ts += "Z"

        return ts

    @staticmethod
    def _parse_details(details: str) -> dict[str, str]:
        """
        Parse Hayabusa Details string into a dict.
        Input:  "Logon Type: 3 | AuthPackage: NTLM | WorkstationName: DESKTOP-ABC"
        Output: {"Logon Type": "3", "AuthPackage": "NTLM", "WorkstationName": "DESKTOP-ABC"}
        """
        result: dict[str, str] = {}
        if not details or details in ("-", "N/A", "n/a"):
            return result
        for part in details.split(" | "):
            part = part.strip()
            if ": " in part:
                key, _, val = part.partition(": ")
                result[key.strip()] = val.strip()
        return result

    @staticmethod
    def _safe_int(value: str) -> int | None:
        if not value:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    def get_stats(self) -> dict[str, Any]:
        return {"records_parsed": self._parsed, "records_skipped": self._skipped}
