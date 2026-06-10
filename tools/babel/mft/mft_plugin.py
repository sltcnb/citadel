"""
MFT Plugin — parses NTFS Master File Table ($MFT) files.
Requires: dissect.ntfs or mft (pip install mft)
Falls back to calling 'analyzeMFT.py' if available.
"""

from __future__ import annotations

import csv
import subprocess
import tempfile
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

try:
    from mft import PyMftParser

    MFT_LIB_AVAILABLE = True
except ImportError:
    MFT_LIB_AVAILABLE = False


class MftPlugin(BasePlugin):
    PLUGIN_NAME = "mft"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "mft"
    SUPPORTED_EXTENSIONS = []
    # NTFS Master File Table — no IANA type; use the de-facto forensic MIME.
    SUPPORTED_MIME_TYPES = ["application/x-ntfs-mft"]

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return ["$MFT", "MFT", "C_MFT", "C_MFT.BAK", "D_MFT", "D_MFT.BAK"]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0
        self._records_skipped = 0

    def parse(self) -> Generator[dict[str, Any], None, None]:
        if MFT_LIB_AVAILABLE:
            yield from self._parse_with_lib()
        elif self._analyze_mft_available():
            yield from self._parse_with_analyzeMFT()
        else:
            raise PluginFatalError(
                "No MFT parser available. Install 'mft' (pip install mft) or 'analyzeMFT.py'."
            )

    def _parse_with_lib(self) -> Generator[dict[str, Any], None, None]:
        try:
            parser = PyMftParser(str(self.ctx.source_file_path))
        except Exception as exc:
            raise PluginFatalError(f"Cannot open MFT: {exc}") from exc

        for entry in parser:
            try:
                if entry is None:
                    continue

                is_dir = entry.is_dir()
                is_deleted = not entry.is_allocated()
                record_num = entry.entry_id

                filename = ""
                filepath = ""
                parent_ref = None
                created = ""
                modified = ""
                accessed = ""
                mft_modified = ""
                fn_created = ""
                fn_modified = ""
                file_size = 0

                # PyMftParser sometimes exposes full_path as an entry attribute —
                # use it when available (it walks the parent chain internally).
                fp_attr = getattr(entry, "full_path", None)
                if fp_attr:
                    filepath = str(fp_attr)

                for attr in entry.attributes():
                    if hasattr(attr, "filename"):
                        fn = attr.filename
                        if fn:
                            filename = str(fn.name) if hasattr(fn, "name") else str(fn)
                            parent_ref = getattr(fn, "parent", parent_ref)
                            # FN-attribute timestamps (anti-forensic detection — these
                            # are harder to backdate than $SI).
                            fn_created = self._ts(getattr(fn, "created", None))
                            fn_modified = self._ts(getattr(fn, "modified", None))
                    if hasattr(attr, "si_timestamps"):
                        si = attr.si_timestamps
                        if si:
                            created = self._ts(si.created)
                            modified = self._ts(si.modified)
                            accessed = self._ts(si.accessed)
                            mft_modified = self._ts(si.mft_modified)
                    if hasattr(attr, "data_size"):
                        file_size = attr.data_size or 0

                if not filepath and filename:
                    filepath = filename

                timestamp = modified or created or ""
                mft_record = {
                    "mft_record_number": record_num,
                    "filename": filename,
                    "filepath": filepath,
                    "parent_ref": parent_ref,
                    "file_size": file_size,
                    "is_directory": is_dir,
                    "is_deleted": is_deleted,
                    "created_at": created,
                    "modified_at": modified,
                    "accessed_at": accessed,
                    "mft_modified_at": mft_modified,
                    "fn_created_at": fn_created,
                    "fn_modified_at": fn_modified,
                }
                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "mft",
                    "timestamp": timestamp,
                    "timestamp_desc": "MFT Modified",
                    "message": (
                        f"{'[DIR]' if is_dir else '[FILE]'}"
                        f"{' [DELETED]' if is_deleted else ''} "
                        f"{filepath or filename}"
                        + (f"  ({file_size:,} bytes)" if file_size and not is_dir else "")
                    ),
                    "mft": mft_record,
                    "raw": mft_record,
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipped MFT entry: %s", exc)

    def _analyze_mft_available(self) -> bool:
        try:
            r = subprocess.run(["analyzeMFT.py", "--help"], capture_output=True, timeout=5)
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _parse_with_analyzeMFT(self) -> Generator[dict[str, Any], None, None]:
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            subprocess.run(
                ["analyzeMFT.py", "-f", str(self.ctx.source_file_path), "-o", tmp_path],
                check=True,
                capture_output=True,
                timeout=600,
            )
        except subprocess.CalledProcessError as exc:
            raise PluginFatalError(f"analyzeMFT.py failed: {exc}") from exc

        def _first(row: dict, *keys: str) -> str:
            for k in keys:
                v = row.get(k)
                if v:
                    return v
            return ""

        with open(tmp_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    self._records_read += 1
                    is_deleted = (
                        "deleted" in _first(row, "Active/Deleted", "Active", "Status").lower()
                    )
                    is_dir = _first(row, "Type", "Record Type") == "Directory"
                    fname = _first(row, "Filename", "Filename #1", "Name")
                    fpath = _first(row, "Full Path", "Filepath", "Path") or fname
                    # analyzeMFT column names changed between versions —
                    # cover the historical and modern formats.
                    created = _first(row, "$SI [C]", "Std Info Created", "SI Created", "Creation")
                    modified = _first(
                        row, "$SI [M]", "Std Info Modified", "SI Modified", "Modified"
                    )
                    accessed = _first(
                        row, "$SI [A]", "Std Info Accessed", "SI Accessed", "Accessed"
                    )
                    record_n = int(_first(row, "Record Number", "Record #", "Entry") or 0)
                    mft_record = {
                        "mft_record_number": record_n,
                        "filename": fname,
                        "filepath": fpath,
                        "is_directory": is_dir,
                        "is_deleted": is_deleted,
                        "created_at": created,
                        "modified_at": modified,
                        "accessed_at": accessed,
                    }
                    yield {
                        "fo_id": str(uuid.uuid4()),
                        "artifact_type": "mft",
                        "timestamp": modified or created or None,
                        "timestamp_desc": "MFT Modified",
                        "message": (
                            f"{'[DIR]' if is_dir else '[FILE]'}"
                            f"{' [DELETED]' if is_deleted else ''} {fpath or fname}"
                        ),
                        "mft": mft_record,
                        "raw": dict(row),
                    }
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped CSV row: %s", exc)

        Path(tmp_path).unlink(missing_ok=True)

    def _ts(self, val: Any) -> str:
        if val is None:
            return ""
        try:
            return str(val)
        except Exception:
            return ""

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_read": self._records_read,
            "records_skipped": self._records_skipped,
        }
