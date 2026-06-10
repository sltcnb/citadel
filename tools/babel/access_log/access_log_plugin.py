"""
Access Log Plugin — parses Apache and Nginx HTTP access logs.

Supports:
  - Combined Log Format (Apache/Nginx default):
      127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /page HTTP/1.1" 200 2326 "http://ref/" "UA"
  - Common Log Format (no referer/UA):
      127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /page HTTP/1.1" 200 2326
  - Nginx error log format:
      2024/01/15 10:30:00 [error] 1234#0: *1 message, client: 1.2.3.4, server: example.com, ...

No extra dependencies required (Python stdlib only).
"""

from __future__ import annotations

import gzip
import re
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

# ── Regex patterns ─────────────────────────────────────────────────────────────

# Combined / Common log format
_ACCESS_RE = re.compile(
    r"^(\S+)\s+"  # client_ip
    r"(\S+)\s+"  # ident (usually -)
    r"(\S+)\s+"  # auth_user
    r"\[([^\]]+)\]\s+"  # [timestamp]
    r'"([^"]*|-)"\s+'  # "METHOD path proto" or -
    r"(\d{3}|-)\s+"  # status code
    r"(\d+|-)"  # bytes sent
    r'(?:\s+"([^"]*)")?'  # referer (optional)
    r'(?:\s+"([^"]*)")?'  # user_agent (optional)
)

# Nginx error log
_NGINX_ERROR_RE = re.compile(
    r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"\[(\w+)\]\s+"  # level
    r"(\d+)#\S+:\s+"  # pid#tid
    r"(.*)"  # message
)

_MONTHS_ABB = {
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
        "access.log",
        "access_log",
        "error.log",
        "error_log",
        "other_vhosts_access.log",
        "ssl_access.log",
        "combined.log",
        "combined_log",
    }
)

# Apache/Nginx virtual-host combined format: vhost:port clientip ident authuser [ts] "req" status bytes
_VHOST_ACCESS_RE = re.compile(
    r"^(\S+)\s+"  # vhost (e.g. www.example.com:80)
    r"(\S+)\s+"  # client_ip
    r"(\S+)\s+"  # ident
    r"(\S+)\s+"  # auth_user
    r"\[([^\]]+)\]\s+"  # [timestamp]
    r'"([^"]*|-)"\s+'  # "METHOD path proto"
    r"(\d{3}|-)\s+"  # status code
    r"(\d+|-)"  # bytes
    r'(?:\s+"([^"]*)")?'  # referer (optional)
    r'(?:\s+"([^"]*)")?'  # user_agent (optional)
)


def _parse_clf_ts(ts_str: str) -> str:
    """
    Convert '10/Oct/2000:13:55:36 -0700' to ISO 8601.
    Returns empty string on failure.
    """
    try:
        # "10/Oct/2000:13:55:36 -0700"
        date_part, tz_part = ts_str.rsplit(" ", 1)
        day, mon_abbr, rest = date_part.split("/", 2)
        year, time_ = rest.split(":", 1)
        month = _MONTHS_ABB.get(mon_abbr, "01")
        # Build naive datetime then attach offset
        tz_sign = 1 if tz_part.startswith("+") else -1
        tz_h = int(tz_part[1:3])
        tz_m = int(tz_part[3:5])
        offset = timezone(timedelta(hours=tz_sign * tz_h, minutes=tz_sign * tz_m))
        dt = datetime(
            int(year),
            int(month),
            int(day),
            int(time_[:2]),
            int(time_[3:5]),
            int(time_[6:8]),
            tzinfo=offset,
        )
        return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ""


class AccessLogPlugin(BasePlugin):
    """Parses Apache and Nginx HTTP access/error log files."""

    PLUGIN_NAME = "access_log"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "access_log"
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
    def _open_log(cls, file_path: Path):
        """Open plain or gzip-compressed log file as a text stream."""
        if file_path.name.lower().endswith(".gz"):
            return gzip.open(file_path, "rt", errors="replace")
        return open(file_path, errors="replace")

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        name = file_path.name.lower()
        if name in _KNOWN_NAMES:
            return True
        # Peek at first lines for CLF / vhost-CLF / nginx-error pattern
        try:
            with cls._open_log(file_path) as fh:
                for _ in range(5):
                    line = fh.readline()
                    if (
                        _ACCESS_RE.match(line)
                        or _VHOST_ACCESS_RE.match(line)
                        or _NGINX_ERROR_RE.match(line)
                    ):
                        return True
        except Exception:
            pass
        return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            fh = self._open_log(path)
        except OSError as exc:
            raise PluginFatalError(f"Cannot open access log: {exc}") from exc

        with fh:
            for raw_line in fh:
                raw_line = raw_line.rstrip("\n")
                if not raw_line.strip():
                    continue
                event = self._parse_line(raw_line)
                if event:
                    self._parsed += 1
                    yield event
                else:
                    self._skipped += 1

    def _parse_line(self, line: str) -> dict | None:
        # Try Virtual Host Combined Format first (vhost:port clientip ...)
        m = _VHOST_ACCESS_RE.match(line)
        if m:
            vhost, client_ip, ident, auth_user, ts_str, request, status, size, referer, ua = (
                m.groups()
            )
            hostname = vhost.split(":")[0] if vhost else ""
            return self._build_access_event(
                line,
                client_ip,
                auth_user,
                ts_str,
                request,
                status,
                size,
                referer,
                ua,
                hostname=hostname,
            )

        # Try Combined / Common Log Format
        m = _ACCESS_RE.match(line)
        if m:
            client_ip, ident, auth_user, ts_str, request, status, size, referer, ua = m.groups()
            return self._build_access_event(
                line,
                client_ip,
                auth_user,
                ts_str,
                request,
                status,
                size,
                referer,
                ua,
            )

        # Try Nginx error log
        m = _NGINX_ERROR_RE.match(line)
        if m:
            ts_str, level, pid, msg_body = m.groups()
            try:
                dt = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S")
                ts = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                ts = ""

            # Extract client IP if present: "client: 1.2.3.4"
            client_ip = ""
            client_m = re.search(r"client:\s*(\S+)", msg_body)
            if client_m:
                client_ip = client_m.group(1).rstrip(",")

            return {
                "fo_id": str(uuid.uuid4()),
                "artifact_type": "access_log",
                "timestamp": ts,
                "timestamp_desc": "Error Time",
                "message": f"[{level.upper()}] {msg_body}",
                "host": {"hostname": ""},
                "network": {"src_ip": client_ip},
                "http": {
                    "method": "",
                    "request_path": "",
                    "protocol": "",
                    "status_code": 0,
                    "response_size": 0,
                    "referer": "",
                    "user_agent": "",
                },
                "error": {"level": level, "pid": pid},
                "raw": {"line": line},
            }

        return None

    def _build_access_event(
        self,
        line: str,
        client_ip: str,
        auth_user: str,
        ts_str: str,
        request: str,
        status: str,
        size: str,
        referer: str | None,
        ua: str | None,
        hostname: str = "",
    ) -> dict:
        ts = _parse_clf_ts(ts_str)
        method = path_req = proto = ""
        if request and request != "-":
            parts = request.split(" ", 2)
            if len(parts) >= 2:
                method, path_req = parts[0], parts[1]
                proto = parts[2] if len(parts) == 3 else ""
        status_int = int(status) if status and status != "-" else 0
        size_int = int(size) if size and size != "-" else 0
        msg = f"{method} {path_req} → {status}"
        if ua and ua != "-":
            msg += f" [{ua[:60]}]"
        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": "access_log",
            "timestamp": ts,
            "timestamp_desc": "Request Time",
            "message": msg,
            "host": {"hostname": hostname},
            "network": {"src_ip": client_ip if client_ip != "-" else ""},
            "http": {
                "method": method,
                "request_path": path_req,
                "protocol": proto,
                "status_code": status_int,
                "response_size": size_int,
                "referer": referer or "",
                "user_agent": ua or "",
            },
            "user": {"name": auth_user if auth_user != "-" else ""},
            "raw": {"line": line},
        }

    def get_stats(self) -> dict[str, Any]:
        return {"records_parsed": self._parsed, "records_skipped": self._skipped}
