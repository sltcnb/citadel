"""
Syslog Plugin — parses Linux/UNIX system log files.

Handles both RFC 3164 (traditional) and RFC 5424 (newer structured) formats:
  - Traditional: "Jan  1 12:34:56 hostname process[pid]: message"
  - RFC 5424:    "<priority>1 2024-01-01T12:34:56.000Z hostname app pid msgid - message"
  - Systemd journal export (key=value lines with __REALTIME_TIMESTAMP)

Recognized filenames: syslog, auth.log, kern.log, daemon.log, messages,
  secure, dmesg, cron.log, mail.log, debug, user.log, and *.log in common paths.

No extra dependencies required (Python stdlib only).
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

# RFC 3164: "Mon DD HH:MM:SS hostname process[pid]: message"
_RFC3164_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"(\S+)\s+"  # hostname
    r"([\w./-]+?)(?:\[(\d+)\])?:\s+"  # process[pid]
    r"(.*)"  # message
)

# RFC 5424: "<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG"
_RFC5424_RE = re.compile(
    r"^<(\d+)>(\d+)\s+"  # <PRI>VERSION
    r"(\S+)\s+"  # TIMESTAMP
    r"(\S+)\s+"  # HOSTNAME
    r"(\S+)\s+"  # APP-NAME
    r"(\S+)\s+"  # PROCID
    r"(\S+)\s+"  # MSGID
    r"(-|\[.*?\])\s*"  # STRUCTURED-DATA
    r"(.*)"  # MSG
)

# Modern rsyslog ISO format (RFC3339), no PRI prefix:
#   "2026-05-31T00:00:40.248878+02:00 master2 kernel: nftables-drop: IN=..."
_ISO_SYSLOG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+"  # ISO ts
    r"(\S+)\s+"  # hostname
    r"([\w.\-/]+?)(?:\[(\d+)\])?:\s+"  # tag[pid]
    r"(.*)"  # message
)


def _strip_rotation(name: str) -> str:
    """Reduce a rotated log filename to its base: kern.log.1 / auth.log.2.gz →
    kern.log / auth.log, so rotation suffixes still match known names."""
    n = name
    if n.endswith(".gz"):
        n = n[:-3]
    return re.sub(r"\.\d+$", "", n)


def _open_text(path: Path):
    """Open a log file as text, transparently decompressing single .gz files."""
    if path.name.lower().endswith(".gz"):
        import gzip

        return gzip.open(path, "rt", errors="replace")
    return open(path, errors="replace")


# Months for RFC 3164 parsing
_MONTHS = {
    "Jan": "01",
    "Feb": "02",
    "Mar": "03",
    "Apr": "04",
    "May": "05",
    "Jun": "06",
    "Jul": "07",
    "Aug": "08",
    "Sep": "09",
    "Oct": "10",
    "Nov": "11",
    "Dec": "12",
}

_KNOWN_NAMES = frozenset(
    {
        "syslog",
        "auth.log",
        "kern.log",
        "daemon.log",
        "messages",
        "secure",
        "dmesg",
        "cron.log",
        "mail.log",
        "debug",
        "user.log",
        "auth",
        "system.log",
        "secure.log",
        "boot.log",
        # Windows text logs
        "cbs.log",
        "windowsupdate.log",
        "dism.log",
        "srttrail.txt",
        "setupapi.dev.log",
        "setupapi.setup.log",
        # Windows Firewall log
        "pfirewall.log",
    }
)

# Extension → artifact_type (used when filename isn't in _FILENAME_ARTIFACT_TYPE)
_EXT_ARTIFACT_TYPE: dict[str, str] = {
    ".log": "syslog",
    ".txt": "text_file",
}

# IIS W3C log pattern — "YYYY-MM-DD HH:MM:SS ..."
_IIS_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} ")

# filename (lowercase) → artifact_type
_FILENAME_ARTIFACT_TYPE: dict[str, str] = {
    # Auth / login
    "auth.log": "auth_log",
    "auth": "auth_log",
    "secure": "auth_log",
    "secure.log": "auth_log",
    # Kernel
    "kern.log": "kern_log",
    "dmesg": "kern_log",
    # Scheduling
    "cron.log": "cron_log",
    # Mail
    "mail.log": "mail_log",
    # System / generic
    "syslog": "syslog",
    "messages": "syslog",
    "daemon.log": "daemon_log",
    "user.log": "user_log",
    "debug": "debug_log",
    "system.log": "syslog",
    "boot.log": "boot_log",
    # Windows text logs
    "cbs.log": "win_log",
    "windowsupdate.log": "win_log",
    "dism.log": "win_log",
    "setupapi.dev.log": "usb_log",
    "setupapi.setup.log": "usb_log",
    "srttrail.txt": "win_log",
    # AnyDesk / TeamViewer
    "anydesk.trace": "remote_access_log",
    "ad_svc.trace": "remote_access_log",
    "connections_incoming.txt": "remote_access_log",
    "connections.txt": "remote_access_log",
}


def _parse_rfc3164_ts(ts_str: str) -> str:
    """Convert 'Jan  1 12:34:56' to a best-effort ISO timestamp (current year)."""
    try:
        parts = ts_str.split()
        month = _MONTHS.get(parts[0], "01")
        day = parts[1].zfill(2)
        time_ = parts[2]
        year = datetime.now(tz=UTC).year
        return f"{year}-{month}-{day}T{time_}Z"
    except (IndexError, KeyError):
        return ""


class SyslogPlugin(BasePlugin):
    """Parses Linux/UNIX syslog files (RFC 3164, RFC 5424)."""

    PLUGIN_NAME = "syslog"
    PLUGIN_PRIORITY = 100
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "syslog"
    SUPPORTED_EXTENSIONS = [".log"]
    SUPPORTED_MIME_TYPES = ["text/plain", "text/x-log"]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._parsed = 0
        self._skipped = 0

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(_KNOWN_NAMES)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        name = file_path.name.lower()
        # Match rotated variants too: kern.log.1, auth.log.2.gz, syslog.1
        if name in _KNOWN_NAMES or _strip_rotation(name) in _KNOWN_NAMES:
            return True
        # Peek at first few lines for syslog patterns (gz-aware)
        try:
            with _open_text(file_path) as fh:
                for _ in range(5):
                    line = fh.readline()
                    if not line:
                        break
                    if _RFC3164_RE.match(line) or _RFC5424_RE.match(line) or _ISO_SYSLOG_RE.match(line):
                        return True
        except OSError:
            pass
        return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        name_lower = _strip_rotation(path.name.lower())
        atype = _FILENAME_ARTIFACT_TYPE.get(name_lower) or _EXT_ARTIFACT_TYPE.get(
            Path(name_lower).suffix.lower(), "syslog"
        )
        try:
            fh = _open_text(path)
        except OSError as exc:
            raise PluginFatalError(f"Cannot open syslog: {exc}") from exc

        with fh:
            for raw_line in fh:
                raw_line = raw_line.rstrip("\n")
                if not raw_line.strip():
                    continue
                # Skip comment/header lines (IIS W3C, Windows Firewall, etc.)
                if raw_line.startswith("#"):
                    continue

                event = self._parse_line(raw_line, atype)
                if event:
                    self._parsed += 1
                    yield event
                else:
                    # Plain-text fallback: emit as generic line so nothing is silently dropped
                    self._parsed += 1
                    yield {
                        "timestamp": None,
                        "timestamp_desc": "Log Line",
                        "message": raw_line.strip(),
                        "artifact_type": atype,
                        "raw": {"line": raw_line},
                    }

    def _parse_line(self, line: str, atype: str = "syslog") -> dict | None:
        # Try RFC 5424 first (more structured)
        m = _RFC5424_RE.match(line)
        if m:
            pri, ver, ts, hostname, app, pid, msgid, sd, msg = m.groups()
            return {
                "fo_id": str(uuid.uuid4()),
                "artifact_type": atype,
                "timestamp": ts if ts != "-" else None,
                "timestamp_desc": "Log Time",
                "message": f"[{app}] {msg}",
                "host": {"hostname": hostname if hostname != "-" else ""},
                "process": {
                    "name": app if app != "-" else "",
                    "pid": pid if pid != "-" else "",
                },
                "syslog": {
                    "facility": int(pri) >> 3 if pri.isdigit() else 0,
                    "severity": int(pri) % 8 if pri.isdigit() else 6,
                    "version": ver,
                    "msgid": msgid if msgid != "-" else "",
                    "structured_data": sd if sd != "-" else "",
                    "raw_message": msg,
                },
                "raw": {"line": line},
            }

        # Modern rsyslog ISO format (no PRI): "<iso> <host> <tag>[pid]: <msg>"
        m = _ISO_SYSLOG_RE.match(line)
        if m:
            ts, hostname, process, pid, msg = m.groups()
            return {
                "fo_id": str(uuid.uuid4()),
                "artifact_type": atype,
                "timestamp": ts,
                "timestamp_desc": "Log Time",
                "message": f"[{process}] {msg}",
                "host": {"hostname": hostname},
                "process": {"name": process, "pid": pid or ""},
                "syslog": {"raw_message": msg},
                "raw": {"line": line},
            }

        # Try RFC 3164
        m = _RFC3164_RE.match(line)
        if m:
            ts_str, hostname, process, pid, msg = m.groups()
            ts = _parse_rfc3164_ts(ts_str)
            return {
                "fo_id": str(uuid.uuid4()),
                "artifact_type": atype,
                "timestamp": ts,
                "timestamp_desc": "Log Time",
                "message": f"[{process}] {msg}",
                "host": {"hostname": hostname},
                "process": {
                    "name": process,
                    "pid": pid or "",
                },
                "syslog": {
                    "facility": 0,
                    "severity": 6,
                    "raw_message": msg,
                },
                "raw": {"line": line},
            }

        return None

    def get_stats(self) -> dict[str, Any]:
        return {"records_parsed": self._parsed, "records_skipped": self._skipped}
