"""
Plaso Plugin — parses Plaso storage files (.plaso) using psort.

Plaso files are SQLite databases with serialized event data.
This plugin:
1. Uses psort.py to export events to JSON (preferred method)
2. Falls back to direct SQLite reading if psort fails
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import tempfile
import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

PLASO_PARSER_TO_ARTIFACT = {
    "winevt": "evtx",
    "winevtx": "evtx",
    "winprefetch": "prefetch",
    "mft": "mft",
    "msiecf": "lnk",
    "lnk": "lnk",
    "winreg": "registry",
    "filestat": "filesystem",
    "sqlite": "browser",
    "chrome_history": "browser",
    "firefox_history": "browser",
    "macos_keychain": "browser",
    "android_history": "browser",
    "cups_destination": "filesystem",
}


def _format_timestamp(ts_value: int) -> str:
    """Convert Plaso timestamp to ISO8601.

    Plaso stores timestamps as microseconds since January 1, 1601 (Windows FILETIME epoch).
    """
    if not ts_value:
        return ""
    try:
        # Plaso/Windows FILETIME: microseconds since 1601-01-01
        # Convert to Unix epoch (1970-01-01) by subtracting offset
        FILETIME_TO_UNIX_EPOCH = 11644473600000000  # microseconds

        if ts_value > FILETIME_TO_UNIX_EPOCH:
            # FILETIME microseconds (most common for plaso)
            unix_ts = (ts_value - FILETIME_TO_UNIX_EPOCH) / 1_000_000
            dt = datetime.fromtimestamp(unix_ts, tz=UTC)
        elif ts_value > 946684800000000:  # Year 2000 in microseconds
            # Microseconds since Unix epoch
            dt = datetime.fromtimestamp(ts_value / 1_000_000, tz=UTC)
        elif ts_value > 946684800:  # Year 2000 in seconds
            # Seconds since Unix epoch
            dt = datetime.fromtimestamp(ts_value, tz=UTC)
        else:
            return ""

        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    except (OSError, OverflowError, ValueError):
        return ""


def _sanitize_for_json(obj: Any) -> Any:
    """Recursively convert an object to be JSON-serializable."""
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", errors="replace")
        except Exception:
            return str(obj)
    if isinstance(obj, dict):
        return {k: _sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_for_json(v) for v in obj]
    if isinstance(obj, (int, float, str, type(None), bool)):
        return obj
    return str(obj)


class PlasoPlugin(BasePlugin):
    PLUGIN_NAME = "plaso"
    PLUGIN_VERSION = "5.0.0"
    DEFAULT_ARTIFACT_TYPE = "timeline"
    SUPPORTED_EXTENSIONS = [".plaso"]
    SUPPORTED_MIME_TYPES = ["application/x-sqlite3"]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0
        self._records_skipped = 0

    def parse(self) -> Generator[dict[str, Any], None, None]:
        """Parse plaso file using psort or SQLite fallback."""
        if self._psort_available():
            self.log.info("Using psort version: %s", self._get_psort_version())
            try:
                yield from self._parse_with_psort()
                if self._records_read > 0:
                    self.log.info("psort succeeded: %d events parsed", self._records_read)
                    return
            except Exception as exc:
                self.log.warning("psort failed: %s. Falling back to SQLite", exc)

        # Fallback to SQLite
        self.log.warning("Using SQLite direct reading (limited data extraction)")
        yield from self._parse_sqlite_direct()

    def _get_psort_version(self) -> str:
        """Get psort version string."""
        name = self._psort_bin()
        if not name:
            return "not found"
        try:
            result = subprocess.run([name, "--version"], capture_output=True, timeout=5)
            return (result.stdout or result.stderr).decode().strip() or "unknown"
        except Exception:
            return "unknown"

    def _psort_bin(self) -> str | None:
        """Return the first working psort binary name, or None if not found.

        Plaso ≥ 20231231 ships 'psort' (no .py suffix).
        Older builds use 'psort.py'.
        """
        for name in ("psort", "psort.py"):
            try:
                result = subprocess.run([name, "--version"], capture_output=True, timeout=5)
                if result.returncode == 0:
                    return name
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                continue
        return None

    def _psort_available(self) -> bool:
        """Check if a working psort binary exists."""
        return self._psort_bin() is not None

    def _parse_with_psort(self) -> Generator[dict[str, Any], None, None]:
        """Export events using psort and parse JSON output."""
        psort = self._psort_bin()
        if not psort:
            raise PluginFatalError("psort binary not found in PATH")

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "output.jsonl"

            cmd = [
                psort,
                "--output-time-zone",
                "UTC",
                "-o",
                "json_line",
                "-w",
                str(output_file),
                str(self.ctx.source_file_path),
            ]

            self.log.info("Running: %s", " ".join(cmd))

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=7200,  # 2 hour timeout for large files
                    env={
                        **os.environ,
                        "PYTHONUNBUFFERED": "1",
                        "LC_ALL": "C.UTF-8",
                        "LANG": "C.UTF-8",
                    },
                )

                if result.returncode != 0:
                    stderr_msg = (
                        result.stderr.decode()[:500] if result.stderr else "no error output"
                    )
                    raise PluginFatalError(f"psort failed (exit {result.returncode}): {stderr_msg}")

                if not output_file.exists() or output_file.stat().st_size == 0:
                    raise PluginFatalError("psort produced no output file")

                self.log.info("psort output: %d bytes", output_file.stat().st_size)

            except subprocess.TimeoutExpired:
                raise PluginFatalError("psort timed out after 2 hours")

            # Parse JSON output
            with output_file.open() as f:
                for i, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        event = self._event_to_fo(data)
                        self._records_read += 1
                        yield event
                        if i > 0 and i % 100000 == 0:
                            self.log.info("Processed %d events", i)
                    except json.JSONDecodeError as exc:
                        self._records_skipped += 1
                        self.log.debug("JSON error line %d: %s", i, exc)
                    except Exception as exc:
                        self._records_skipped += 1
                        self.log.debug("Skipped line %d: %s", i, exc)

    def _event_to_fo(self, data: dict) -> dict[str, Any]:
        """Convert psort JSON event to ForensicEvent format."""
        parser = data.get("data_type", "") or data.get("parser", "") or "unknown"
        artifact_type = self._resolve_artifact_type(parser) if parser else "timeline"

        timestamp = data.get("datetime", "") or data.get("timestamp", "") or ""
        hostname = data.get("hostname", "") or ""
        username = data.get("username", "") or ""

        # Build message from available fields
        message = (
            data.get("message", "")
            or data.get("description", "")
            or data.get("display_name", "")
            or data.get("filename", "")
            or ""
        )

        if not message:
            source_short = data.get("source_short", "") or ""
            source_long = data.get("source_long", "") or ""
            if source_short or source_long:
                message = f"{source_short}: {source_long}"
            else:
                message = f"[{parser}] Event"

        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": artifact_type,
            "timestamp": timestamp,
            "timestamp_desc": data.get("timestamp_desc", "") or "Event Time",
            "message": message[:2000] if message else "",
            "host": {"hostname": str(hostname)},
            "user": {"name": str(username)},
            "plaso": {
                "parser": parser,
                "data_type": parser,
                "filename": data.get("filename", "") or "",
                "display_name": data.get("display_name", "") or "",
                "source_short": data.get("source_short", "") or "",
                "source_long": data.get("source_long", "") or "",
            },
            "raw": _sanitize_for_json(data),
        }

    def _parse_sqlite_direct(self) -> Generator[dict[str, Any], None, None]:
        """Extract events directly from SQLite when psort fails.

        Note: This only extracts timestamps and event IDs. Full event data
        is serialized in BLOBs that require psort to deserialize.
        """
        db_path = str(self.ctx.source_file_path)
        self.log.info("Opening plaso SQLite: %s", db_path)

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
        except sqlite3.DatabaseError as exc:
            raise PluginFatalError(f"Cannot open SQLite: {exc}") from exc

        try:
            cursor = conn.cursor()

            # Get table info
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            self.log.info("Tables: %s", tables)

            if "event" not in tables:
                raise PluginFatalError("No 'event' table found in plaso file")

            # Get row count
            cursor.execute("SELECT COUNT(*) FROM event")
            count = cursor.fetchone()[0]
            self.log.info("Total events in 'event' table: %d", count)

            # Sample first timestamp for debugging
            cursor.execute("SELECT _timestamp FROM event LIMIT 1")
            sample = cursor.fetchone()
            if sample and sample[0]:
                ts = sample[0]
                formatted = _format_timestamp(ts)
                self.log.info("Sample timestamp: %d -> %s", ts, formatted or "NULL")

            # Extract events (limit to prevent memory issues)
            max_events = 2000000
            cursor.execute(
                f"SELECT _identifier, _timestamp FROM event ORDER BY _timestamp ASC LIMIT {max_events}"
            )

            while True:
                rows = cursor.fetchmany(10000)
                if not rows:
                    break

                for row in rows:
                    try:
                        raw_id = row[0]
                        ts_value = row[1]

                        # SQLite may return _identifier as BLOB → bytes.
                        # Normalise to a JSON-safe string (hex for BLOB, str otherwise).
                        if isinstance(raw_id, bytes):
                            event_id = raw_id.hex()
                        elif raw_id is not None:
                            event_id = str(raw_id)
                        else:
                            event_id = ""

                        timestamp = _format_timestamp(ts_value) if ts_value else ""

                        self._records_read += 1
                        yield {
                            "fo_id": str(uuid.uuid4()),
                            "artifact_type": "timeline",
                            "timestamp": timestamp if timestamp else None,
                            "timestamp_desc": "Event Time",
                            "message": f"[Plaso Event #{event_id}]",
                            "host": {"hostname": ""},
                            "user": {"name": ""},
                            "plaso": {
                                "parser": "unknown",
                                "data_type": "unknown",
                                "note": "Full event data requires psort binary",
                                "event_id": event_id,
                                "raw_timestamp": ts_value
                                if isinstance(ts_value, (int, float, str, type(None)))
                                else str(ts_value),
                            },
                            "raw": {"_identifier": event_id, "_timestamp": ts_value},
                        }
                    except Exception as exc:
                        self._records_skipped += 1
                        self.log.error("Skipped event (id=%s): %s", repr(row[0]), exc)

                if self._records_read % 50000 == 0 and self._records_read > 0:
                    self.log.info("Processed %d events...", self._records_read)

            self.log.info(
                "SQLite extraction complete: %d events (max %d). "
                "For full data, install/fix psort: apt-get install plaso-tools",
                self._records_read,
                max_events,
            )

        finally:
            conn.close()

    def _resolve_artifact_type(self, parser: str) -> str:
        """Map plaso parser name to artifact_type."""
        parser_lower = parser.lower()
        for prefix, artifact_type in PLASO_PARSER_TO_ARTIFACT.items():
            if parser_lower.startswith(prefix):
                return artifact_type
        return self.DEFAULT_ARTIFACT_TYPE

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_read": self._records_read,
            "records_skipped": self._records_skipped,
        }

    @classmethod
    def create_from_source(
        cls, source_file: Path, work_dir: Path, ctx: PluginContext
    ) -> PlasoPlugin:
        """Create plaso file from arbitrary source using log2timeline."""
        plaso_path = work_dir / f"{source_file.name}.plaso"
        # plaso >= 20231231 ships 'log2timeline' (no .py); older builds use 'log2timeline.py'
        l2t_bin = None
        for name in ("log2timeline", "log2timeline.py"):
            if subprocess.run(["which", name], capture_output=True).returncode == 0:
                l2t_bin = name
                break
        if not l2t_bin:
            raise PluginFatalError("log2timeline binary not found in PATH")

        cmd = [
            l2t_bin,
            "--status_view",
            "none",
            "--logfile",
            "/dev/null",
            str(plaso_path),
            str(source_file),
        ]
        ctx.logger.info("[%s] log2timeline: processing %s", ctx.job_id, source_file.name)

        try:
            result = subprocess.run(cmd, check=True, capture_output=True, timeout=7200)
            if result.stderr:
                ctx.logger.info("log2timeline stderr: %s", result.stderr.decode()[:500])
        except FileNotFoundError as exc:
            raise PluginFatalError(f"{l2t_bin} not found in PATH") from exc
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode()[:500] if exc.stderr else "no output"
            raise PluginFatalError(
                f"log2timeline failed (exit {exc.returncode}): {stderr}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise PluginFatalError("log2timeline timed out after 2 hours") from exc

        if not plaso_path.exists() or plaso_path.stat().st_size == 0:
            raise PluginFatalError("log2timeline produced no output")

        return cls(
            PluginContext(
                case_id=ctx.case_id,
                job_id=ctx.job_id,
                source_file_path=plaso_path,
                source_minio_url=ctx.source_minio_url,
                logger=ctx.logger,
            )
        )
