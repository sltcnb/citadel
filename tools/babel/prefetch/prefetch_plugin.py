"""
Prefetch Plugin — parses Windows Prefetch (.pf) files.
Supports versions 17 (XP), 23 (Vista/7), 26 (Win8.1), 30 (Win10+).
Win8.1+ files use MAM compression (decompressed via libscca if available).
"""

from __future__ import annotations

import json
import struct
import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError, PluginParseError

# Try libscca first (handles compressed formats)
try:
    import pyscca

    PYSCCA_AVAILABLE = True
except ImportError:
    PYSCCA_AVAILABLE = False

SIGNATURE = b"SCCA"
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
FILETIME_100NS = 10_000_000  # 100-nanosecond intervals per second


def filetime_to_iso(filetime: int) -> str:
    """Convert a Windows FILETIME (100-ns intervals since 1601-01-01) to ISO8601."""
    if filetime == 0:
        return ""
    try:
        seconds = filetime / FILETIME_100NS
        dt = FILETIME_EPOCH + __import__("datetime").timedelta(seconds=seconds)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    except (OverflowError, ValueError):
        return ""


class PrefetchPlugin(BasePlugin):
    PLUGIN_NAME = "prefetch"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "prefetch"
    SUPPORTED_EXTENSIONS = [".pf"]
    # Windows Prefetch (SCCA) — no IANA type; de-facto forensic MIME.
    SUPPORTED_MIME_TYPES = ["application/x-ms-prefetch"]
    PLUGIN_PRIORITY = 110  # specific binary format — beats every text fallback

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0
        self._records_skipped = 0

    def parse(self) -> Generator[dict[str, Any], None, None]:
        file_path = self.ctx.source_file_path

        if PYSCCA_AVAILABLE:
            yield from self._parse_with_pyscca(file_path)
        else:
            yield from self._parse_raw(file_path)

    def _parse_with_pyscca(self, file_path: Path) -> Generator[dict[str, Any], None, None]:
        """Parse using libscca Python bindings (handles all versions including compressed)."""
        try:
            pf = pyscca.open(str(file_path))
        except Exception as exc:
            raise PluginFatalError(f"pyscca cannot open {file_path.name}: {exc}") from exc

        try:
            exe_name = pf.executable_filename or file_path.stem
            run_count = pf.run_count
            prefetch_hash = f"{pf.prefetch_hash:08X}"

            last_run_times = []
            for i in range(8):
                try:
                    ts = pf.get_last_run_time(i)
                    if ts and ts.year > 1601:
                        last_run_times.append(ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z")
                except Exception:
                    break

            file_metrics = []
            for i in range(pf.number_of_file_metrics_entries):
                try:
                    entry = pf.get_file_metrics_entry(i)
                    file_metrics.append(
                        {
                            "filename": entry.filename or "",
                            "file_reference": entry.file_reference or "",
                        }
                    )
                except Exception:
                    continue

            volumes = []
            for i in range(pf.number_of_volumes):
                try:
                    vol = pf.get_volume_information(i)
                    volumes.append(
                        {
                            "device_path": vol.device_path or "",
                            "creation_time": vol.creation_time.strftime("%Y-%m-%dT%H:%M:%S.%f")
                            + "Z"
                            if vol.creation_time
                            else "",
                            "serial_number": f"{vol.serial_number:08X}"
                            if vol.serial_number
                            else "",
                        }
                    )
                except Exception:
                    continue

            # Use the most recent run time as the event timestamp
            timestamp = last_run_times[0] if last_run_times else ""
            message = f"{exe_name} executed {run_count} time(s), last: {timestamp or 'unknown'}"

            _raw_src = {
                "executable_filename": exe_name,
                "prefetch_hash": prefetch_hash,
                "run_count": run_count,
                "last_run_times": last_run_times,
                "file_metrics": file_metrics,
                "volumes": volumes,
            }
            event = {
                "fo_id": str(uuid.uuid4()),
                "artifact_type": "prefetch",
                "timestamp": timestamp,
                "timestamp_desc": "Last Run Time",
                "message": message,
                "process": {
                    "name": exe_name,
                    "path": exe_name,
                },
                "prefetch": {
                    "executable_name": exe_name,
                    "prefetch_hash": prefetch_hash,
                    "run_count": run_count,
                    "last_run_times": last_run_times,
                    "file_metrics": file_metrics,
                    "volumes": volumes,
                    "file_metrics_count": len(file_metrics),
                },
                "raw": {"line": json.dumps(_raw_src, default=str)},
            }
            self._records_read += 1
            yield event

            # Also yield individual run time events for timeline accuracy
            for i, rt in enumerate(last_run_times[1:], start=1):
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "prefetch",
                    "timestamp": rt,
                    "timestamp_desc": f"Run Time #{i + 1}",
                    "message": f"{exe_name} executed (run #{i + 1})",
                    "process": {"name": exe_name},
                    "prefetch": {
                        "executable_name": exe_name,
                        "prefetch_hash": prefetch_hash,
                        "run_count": run_count,
                        "run_index": i + 1,
                        "last_run_times": last_run_times,
                    },
                    "raw": {
                        "line": json.dumps(
                            {
                                "executable_filename": exe_name,
                                "prefetch_hash": prefetch_hash,
                                "run_count": run_count,
                                "run_index": i + 1,
                                "run_time": rt,
                            },
                            default=str,
                        )
                    },
                }

        finally:
            pf.close()

    def _parse_raw(self, file_path: Path) -> Generator[dict[str, Any], None, None]:
        """
        Fallback raw parser for Windows 7 (version 23) uncompressed prefetch.
        Version 26/30 (Win8.1+) use MAM compression and require libscca.
        """
        try:
            data = file_path.read_bytes()
        except OSError as exc:
            raise PluginFatalError(f"Cannot read {file_path.name}: {exc}") from exc

        if len(data) < 84:
            raise PluginFatalError("File too small to be a valid prefetch file")

        version = struct.unpack_from("<I", data, 0)[0]
        signature = data[4:8]

        if signature != SIGNATURE:
            raise PluginFatalError(f"Invalid prefetch signature: {signature!r}")

        if version in (26, 30):
            self.log.warning(
                "%s uses MAM compression (Win8.1+). Install pyscca for full support.",
                file_path.name,
            )
            raise PluginFatalError(
                "MAM-compressed prefetch requires pyscca. Install libscca-python."
            )

        # Parse version 17 (XP) and 23 (Vista/7) — uncompressed
        try:
            exe_name = data[16:76].decode("utf-16-le", errors="ignore").rstrip("\x00")
            exe_name = exe_name.split("\x00")[0]
            pf_hash = struct.unpack_from("<I", data, 76)[0]
            prefetch_hash = f"{pf_hash:08X}"

            if version == 17:
                run_count = struct.unpack_from("<I", data, 100)[0]
                last_run_ft = struct.unpack_from("<Q", data, 80)[0]
                last_run_times = [filetime_to_iso(last_run_ft)] if last_run_ft else []
            else:  # version 23
                run_count = struct.unpack_from("<I", data, 152)[0]
                # 8 last run times at offset 128
                last_run_times = []
                for i in range(8):
                    ft = struct.unpack_from("<Q", data, 128 + i * 8)[0]
                    ts = filetime_to_iso(ft)
                    if ts:
                        last_run_times.append(ts)

            timestamp = last_run_times[0] if last_run_times else ""
            message = f"{exe_name} executed {run_count} time(s), last: {timestamp or 'unknown'}"

            self._records_read += 1
            yield {
                "fo_id": str(uuid.uuid4()),
                "artifact_type": "prefetch",
                "timestamp": timestamp,
                "timestamp_desc": "Last Run Time",
                "message": message,
                "process": {"name": exe_name},
                "prefetch": {
                    "executable_name": exe_name,
                    "prefetch_hash": prefetch_hash,
                    "run_count": run_count,
                    "last_run_times": last_run_times,
                    "format_version": version,
                },
                "raw": {
                    "line": json.dumps(
                        {
                            "executable_name": exe_name,
                            "prefetch_hash": prefetch_hash,
                            "run_count": run_count,
                            "last_run_times": last_run_times,
                            "format_version": version,
                        },
                        default=str,
                    )
                },
            }

        except struct.error as exc:
            raise PluginParseError(f"Struct parsing failed: {exc}") from exc

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_read": self._records_read,
            "records_skipped": self._records_skipped,
            "parser": "pyscca" if PYSCCA_AVAILABLE else "raw",
        }
