"""
Jump List (*.automaticDestinations-ms) plugin.

Parses Windows Jump Lists — the per-application MRU of files/URLs a user opened.
An AutomaticDestinations file is an OLE compound document holding a ``DestList``
stream (the MRU index: target path + access count + last-used FILETIME) plus one
numbered stream per entry (an embedded .lnk). This decodes the DestList into
file-access / execution events. The AppId in the filename identifies the app.

Requires ``olefile`` (graceful failure with an install hint if absent).
"""

from __future__ import annotations

import struct
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

try:
    import olefile  # type: ignore
    _OLE = True
except Exception:  # pragma: no cover
    _OLE = False

_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

# A few well-known Jump List AppIds → app name (there are hundreds; this covers
# the common ones, everything else falls back to the raw AppId).
_APPIDS = {
    "1b4dd67f29cb1962": "Windows Explorer",
    "5f7b5f1e01b83767": "Quick Access",
    "9b9cdc69c1c24e2b": "Notepad",
    "adecfb853d77462a": "Word",
    "9d1f905ce5044aee": "WordPad",
    "f01b4d95cf55d32a": "Explorer (This PC)",
}


def _ft_iso(ft: int) -> str:
    if not ft or ft <= 0:
        return ""
    try:
        return (_EPOCH + timedelta(microseconds=ft / 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return ""


class JumpListPlugin(BasePlugin):
    """Parses Windows AutomaticDestinations Jump Lists (DestList MRU)."""

    PLUGIN_NAME = "jumplist"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "jumplist"
    SUPPORTED_EXTENSIONS = [".automaticdestinations-ms", ".customdestinations-ms"]
    SUPPORTED_MIME_TYPES = ["application/octet-stream", "application/x-ole-storage"]
    PLUGIN_PRIORITY = 94

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return []

    @classmethod
    def can_handle(cls, file_path, mime_type) -> bool:
        n = file_path.name.lower()
        if "automaticdestinations" in n or "customdestinations" in n:
            return True
        # OLE compound magic
        try:
            with open(file_path, "rb") as fh:
                return fh.read(8) == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        except OSError:
            return False

    def _app_name(self) -> str:
        stem = self.ctx.source_file_path.name.lower().split(".automaticdestinations")[0].split(".customdestinations")[0]
        appid = stem.split("_")[-1]  # collector prefixes with user/dir
        return _APPIDS.get(appid, appid or stem)

    def parse(self) -> Generator[dict[str, Any], None, None]:
        if not _OLE:
            raise PluginFatalError(
                "olefile is not installed. Run: pip install olefile (needed for Jump Lists)."
            )
        path = self.ctx.source_file_path
        app = self._app_name()
        try:
            if not olefile.isOleFile(str(path)):
                return
            ole = olefile.OleFileIO(str(path))
        except Exception as exc:
            raise PluginFatalError(f"Not a valid Jump List OLE file: {exc}") from exc
        try:
            if not ole.exists("DestList"):
                return
            data = ole.openstream("DestList").read()
            yield from self._parse_destlist(data, app, str(path))
        finally:
            try:
                ole.close()
            except Exception:
                pass

    def _parse_destlist(self, data: bytes, app: str, src: str) -> Generator[dict[str, Any], None, None]:
        if len(data) < 32:
            return
        # Header: version(4) at 0; entries count etc. Entry layout differs by
        # version; the path (UTF-16) + last-used FILETIME are the load-bearing
        # fields. Parse defensively — a bad offset ends this file cleanly.
        try:
            version = struct.unpack_from("<I", data, 0)[0]
        except struct.error:
            return
        # Header size: 32 (v1) / 32 (v3+). Entries start at 32.
        off = 32
        n = 0
        while off + 130 < len(data) and n < 2000:
            try:
                # v1 entry is 114 bytes fixed header before path-len; v3/v4 use a
                # variable header. The last-used FILETIME sits at +100, the
                # UTF-16 path-length (chars) at +128, path at +130.
                ft = struct.unpack_from("<Q", data, off + 100)[0]
                path_len = struct.unpack_from("<H", data, off + 128)[0]
                if path_len == 0 or path_len > 2048:
                    break
                p_start = off + 130
                target = data[p_start:p_start + path_len * 2].decode("utf-16-le", errors="replace")
                # v1 has a 4-byte trailer after the path; v3/v4 have none.
                off = p_start + path_len * 2 + (4 if version == 1 else 0)
                n += 1
            except (struct.error, UnicodeDecodeError):
                break
            if not target.strip():
                continue
            last = _ft_iso(ft)
            fname = target.replace("/", "\\").split("\\")[-1]
            yield {
                "timestamp": last or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "timestamp_desc": "File Opened (Jump List)",
                "message": f"JumpList [{app}]: {target}",
                "artifact_type": "jumplist",
                "os": "windows",
                "file": {"path": target, "name": fname},
                "jumplist": {"app": app, "target": target, "last_used": last, "entry": n},
                "raw": {"content": target},
            }

    def get_stats(self) -> dict[str, Any]:
        return {}
