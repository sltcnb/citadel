"""
Recycle Bin ($I) plugin.

Parses Windows Vista+ Recycle Bin ``$I`` metadata files — one per deleted item,
holding the ORIGINAL path, the original size, and the DELETION timestamp. The
companion ``$R`` file holds the recovered content (collected alongside, parsed
by content-type). Pure-stdlib (struct); handles both the pre-Win10 fixed-path
layout (version 1) and the Win10+ length-prefixed layout (version 2).
"""

from __future__ import annotations

import struct
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def _filetime(ft: int) -> str:
    if ft <= 0:
        return ""
    try:
        return (_EPOCH + timedelta(microseconds=ft / 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return ""


class RecycleBinPlugin(BasePlugin):
    """Parses Recycle Bin $I deleted-file metadata records."""

    PLUGIN_NAME = "recyclebin"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "recyclebin"
    SUPPORTED_EXTENSIONS = []  # $I files have no extension
    SUPPORTED_MIME_TYPES = ["application/octet-stream"]
    PLUGIN_PRIORITY = 95

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return []

    @classmethod
    def can_handle(cls, file_path, mime_type) -> bool:
        name = file_path.name
        # $I files are named $I<6 chars><ext>; a bare "$I" prefix is the strong signal.
        if "$I" in name or "_$I" in name or name.startswith("$I"):
            try:
                with open(file_path, "rb") as fh:
                    ver = struct.unpack("<q", fh.read(8))[0]
                return ver in (1, 2)
            except (OSError, struct.error):
                return False
        return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise PluginFatalError(f"Cannot read $I file: {exc}") from exc
        if len(data) < 24:
            return
        try:
            version, size = struct.unpack("<qq", data[:16])
            del_ft = struct.unpack("<q", data[16:24])[0]
        except struct.error:
            return

        if version == 2:
            if len(data) < 28:
                return
            name_len = struct.unpack("<i", data[24:28])[0]  # wchar count incl NUL
            raw = data[28:28 + name_len * 2]
        else:  # version 1 — fixed 260-wchar path
            raw = data[24:24 + 260 * 2]
        try:
            orig_path = raw.decode("utf-16-le", errors="replace").split("\x00")[0]
        except Exception:
            orig_path = ""
        if not orig_path:
            return

        deleted = _filetime(del_ft)
        fname = orig_path.replace("/", "\\").split("\\")[-1]
        yield {
            "timestamp": deleted or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "timestamp_desc": "File Deleted (Recycle Bin)",
            "message": f"Deleted: {orig_path}" + (f"  ({size:,} bytes)" if size >= 0 else ""),
            "artifact_type": "recyclebin",
            "os": "windows",
            "file": {"path": orig_path, "name": fname, "size": size if size >= 0 else None},
            "recyclebin": {
                "original_path": orig_path,
                "original_size": size,
                "deleted_time": deleted,
                "format_version": version,
            },
            "raw": {"content": f"version={version} size={size} deleted={deleted} path={orig_path}"},
        }

    def get_stats(self) -> dict[str, Any]:
        return {}
