"""
utmp / wtmp / btmp plugin — Linux login accounting records.

These are fixed-width binary files (struct utmp, 384 bytes per record on
glibc/Linux x86-64). They are the authoritative source for:
  - wtmp  : login / logout history + reboots  (what `last` reads)
  - btmp  : failed login attempts             (what `lastb` reads)
  - utmp  : currently logged-in sessions      (what `who` reads)

The collector grabs these raw, so without a dedicated parser they fall to
the strings fallback and produce garbage (usernames smeared together with
tty names). This plugin unpacks the real records into typed login events.

Pure stdlib (struct). No external dependencies.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

# struct utmp (Linux, glibc) — little-endian, 384 bytes:
#   short ut_type; (2)  + 2 pad
#   pid_t ut_pid; (4)
#   char  ut_line[32];
#   char  ut_id[4];
#   char  ut_user[32];
#   char  ut_host[256];
#   struct { short e_termination; short e_exit; } ut_exit; (4)
#   int32 ut_session; (4)
#   struct { int32 tv_sec; int32 tv_usec; } ut_tv; (8)
#   int32 ut_addr_v6[4]; (16)
#   char  __unused[20];
_UTMP_FMT = "<hxxi32s4s32s256shhiii16s20s"
_UTMP_SIZE = struct.calcsize(_UTMP_FMT)  # 384

# ut_type → label
_UT_TYPE = {
    0: "EMPTY",
    1: "RUN_LVL",
    2: "BOOT_TIME",
    3: "NEW_TIME",
    4: "OLD_TIME",
    5: "INIT_PROCESS",
    6: "LOGIN_PROCESS",
    7: "USER_PROCESS",
    8: "DEAD_PROCESS",
    9: "ACCOUNTING",
}

_HANDLED = {"WTMP", "BTMP", "UTMP"}


def _cstr(raw: bytes) -> str:
    """Decode a NUL-padded C string field."""
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()


def _decode_addr(addr16: bytes) -> str:
    """ut_addr_v6 holds an IPv4 (first word) or full IPv6. Return a printable IP."""
    try:
        words = struct.unpack("<4I", addr16)
    except struct.error:
        return ""
    # IPv4: only the first 32-bit word is set.
    if words[1] == 0 and words[2] == 0 and words[3] == 0:
        if words[0] == 0:
            return ""
        return socket.inet_ntop(socket.AF_INET, addr16[:4])
    try:
        return socket.inet_ntop(socket.AF_INET6, addr16)
    except (OSError, ValueError):
        return ""


class UtmpPlugin(BasePlugin):
    PLUGIN_NAME = "utmp"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "login_event"
    SUPPORTED_EXTENSIONS = []
    # Linux wtmp/utmp/btmp accounting record — no IANA type.
    SUPPORTED_MIME_TYPES = ["application/x-utmp"]
    PLUGIN_PRIORITY = 110  # beat strings/plaso and any generic text claim

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(_HANDLED)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        # Match wtmp / btmp / utmp and their rotations (wtmp.1, btmp.old, ...).
        stem = file_path.name.split(".", 1)[0].upper()
        return stem in _HANDLED or super().can_handle(file_path, mime_type)

    def _source_kind(self) -> str:
        stem = self.ctx.source_file_path.name.split(".", 1)[0].lower()
        return {"wtmp": "login history", "btmp": "failed login", "utmp": "active session"}.get(
            stem, "login"
        )

    def parse(self) -> Generator[dict[str, Any], None, None]:
        fp = self.ctx.source_file_path
        kind = self._source_kind()
        is_btmp = fp.name.lower().startswith("btmp")
        try:
            data = fp.read_bytes()
        except Exception as exc:
            raise PluginFatalError(f"Cannot read utmp file: {exc}")

        if len(data) < _UTMP_SIZE:
            return

        count = 0
        for off in range(0, len(data) - _UTMP_SIZE + 1, _UTMP_SIZE):
            rec = data[off : off + _UTMP_SIZE]
            try:
                (
                    ut_type,
                    ut_pid,
                    ut_line,
                    ut_id,
                    ut_user,
                    ut_host,
                    _term,
                    _exit,
                    _session,
                    tv_sec,
                    _tv_usec,
                    ut_addr,
                    _unused,
                ) = struct.unpack(_UTMP_FMT, rec)
            except struct.error:
                continue

            user = _cstr(ut_user)
            line = _cstr(ut_line)
            host = _cstr(ut_host)
            addr = _decode_addr(ut_addr)
            type_name = _UT_TYPE.get(ut_type, f"TYPE_{ut_type}")

            # Skip empty filler records (no user, no time, EMPTY type).
            if ut_type == 0 and not user and not tv_sec:
                continue
            if tv_sec <= 0 and not user and type_name not in ("RUN_LVL", "BOOT_TIME"):
                continue

            try:
                ts = datetime.fromtimestamp(tv_sec, tz=UTC).isoformat() if tv_sec > 0 else ""
            except (OSError, OverflowError, ValueError):
                ts = ""

            src_ip = addr or (host if host and any(c.isdigit() for c in host) else "")
            if is_btmp:
                verb = "Failed login"
            elif type_name == "USER_PROCESS":
                verb = "Login"
            elif type_name == "DEAD_PROCESS":
                verb = "Logout / session end"
            elif type_name == "BOOT_TIME":
                verb = "System boot"
            elif type_name == "RUN_LVL":
                verb = "Runlevel change"
            else:
                verb = type_name

            parts = [verb]
            if user:
                parts.append(f"user={user}")
            if line:
                parts.append(f"tty={line}")
            if host:
                parts.append(f"from={host}")
            elif src_ip:
                parts.append(f"from={src_ip}")
            message = "  ".join(parts)

            user_obj: dict[str, Any] = {}
            if user:
                user_obj["name"] = user
            net_obj: dict[str, Any] = {}
            if src_ip:
                net_obj["source_ip"] = src_ip

            yield self.make_event(
                timestamp=ts,
                timestamp_desc=kind.title(),
                message=message,
                artifact_type="login_event",
                user=user_obj or None,
                network=net_obj or None,
                process={"pid": ut_pid} if ut_pid else None,
                raw={
                    "source": fp.name,
                    "kind": kind,
                    "ut_type": ut_type,
                    "ut_type_name": type_name,
                    "user": user,
                    "tty": line,
                    "id": _cstr(ut_id),
                    "host": host,
                    "addr": addr,
                    "pid": ut_pid,
                    "tv_sec": tv_sec,
                },
                login_event={
                    "kind": kind,
                    "type": type_name,
                    "user": user,
                    "tty": line,
                    "host": host,
                    "source_ip": src_ip,
                    "pid": ut_pid,
                    "failed": is_btmp,
                },
            )
            count += 1
        self._count = count

    def get_stats(self) -> dict[str, Any]:
        return {"records": getattr(self, "_count", 0)}
