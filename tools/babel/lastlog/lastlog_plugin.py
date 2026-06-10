"""lastlog parser — /var/log/lastlog.

A fixed-size binary file: one 292-byte record per UID (record index == UID),
recording that user's most recent login. Layout (glibc struct lastlog):

    int32  ll_time          # epoch seconds, little-endian
    char   ll_line[32]      # tty (UT_LINESIZE)
    char   ll_host[256]     # source host / IP (UT_HOSTSIZE)

Empty records (never-logged-in UIDs) are skipped. Each populated record becomes
a login event carrying the source IP and tty — exactly what gets buried when the
file falls through to the strings fallback.
"""
from __future__ import annotations

import struct
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError, iso_z

_RECORD = struct.Struct("<i32s256s")  # 4 + 32 + 256 = 292 bytes
_RECORD_SIZE = 292


def _cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()


class LastlogPlugin(BasePlugin):
    """Parses the Linux /var/log/lastlog binary (last login per UID)."""

    PLUGIN_NAME = "lastlog"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "login_event"
    SUPPORTED_EXTENSIONS: list[str] = []  # extensionless; matched by filename
    SUPPORTED_MIME_TYPES: list[str] = []
    PLUGIN_PRIORITY = 80  # beat the strings/binary fallback

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._parsed = 0

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return ["LASTLOG"]  # matched case-insensitively by BasePlugin.can_handle

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        if file_path.name.lower() != "lastlog":
            return False
        # Must be a whole number of fixed-size records.
        try:
            return file_path.stat().st_size % _RECORD_SIZE == 0 and file_path.stat().st_size > 0
        except OSError:
            return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise PluginFatalError(f"Cannot read lastlog: {exc}") from exc

        for uid, off in enumerate(range(0, len(data) - _RECORD_SIZE + 1, _RECORD_SIZE)):
            ll_time, line_b, host_b = _RECORD.unpack_from(data, off)
            line = _cstr(line_b)
            host = _cstr(host_b)
            if ll_time == 0 and not line and not host:
                continue  # never logged in
            self._parsed += 1
            evt = {
                "fo_id": str(uuid.uuid4()),
                "artifact_type": "login_event",
                "timestamp": iso_z(ll_time) if ll_time else None,
                "timestamp_desc": "Last Login",
                "message": f"Last login: UID {uid} from {host or 'local'} on {line or '?'}",
                "user": {"id": str(uid)},
                "login_event": {
                    "uid": uid,
                    "tty": line,
                    "source": host,
                    "source_type": "lastlog",
                },
                "raw": {"uid": uid, "ll_time": ll_time, "line": line, "host": host},
            }
            if host:
                evt["host"] = {"hostname": host}
                evt["network"] = {"src_ip": host}
            yield evt

    def get_stats(self) -> dict[str, Any]:
        return {"records_parsed": self._parsed}
