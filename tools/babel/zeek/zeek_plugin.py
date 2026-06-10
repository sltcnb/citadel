"""
Zeek Plugin — parses Zeek/Bro network log files.

Zeek uses a TSV format with a header block:
  #separator \\x09
  #set_separator ,
  #empty_field (empty)
  #unset_field -
  #path conn
  #open YYYY-MM-DD-HH-MM-SS
  #fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto ...
  #types time string addr port addr port enum ...

Handles: conn, dns, http, ssl, ssh, ftp, smtp, files, weird log types.
No extra dependencies required (Python stdlib only).
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

_ZEEK_NAMES = frozenset(
    {
        "conn.log",
        "dns.log",
        "http.log",
        "ssl.log",
        "ssh.log",
        "ftp.log",
        "smtp.log",
        "files.log",
        "weird.log",
        "notice.log",
        "dpd.log",
        "tunnel.log",
        "rdp.log",
        "smb_mapping.log",
        "smb_files.log",
        "kerberos.log",
        "x509.log",
        "pe.log",
    }
)


def _zeek_ts(ts_str: str) -> str:
    """Convert Zeek epoch timestamp ('1234567890.123456') to ISO-8601."""
    try:
        epoch = float(ts_str)
        return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (ValueError, TypeError, OverflowError):
        return ts_str


def _is_unset(val: str, unset: str, empty: str) -> bool:
    return val == unset or val == empty


class ZeekPlugin(BasePlugin):
    """Parses Zeek/Bro network log files (TSV format with #fields header)."""

    PLUGIN_NAME = "zeek"
    PLUGIN_PRIORITY = 100
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "zeek"
    SUPPORTED_EXTENSIONS = [".log"]
    SUPPORTED_MIME_TYPES = ["text/plain", "text/x-log"]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._parsed = 0
        self._skipped = 0

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(_ZEEK_NAMES)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        if file_path.name.lower() in _ZEEK_NAMES:
            return True
        # Detect by presence of Zeek header markers
        try:
            with open(file_path, errors="replace") as fh:
                for _ in range(12):
                    line = fh.readline()
                    if line.startswith("#fields"):
                        return True
                    if line.startswith("#separator") or line.startswith("#path"):
                        continue
                    if line and not line.startswith("#"):
                        break
        except OSError:
            pass
        return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open Zeek log: {exc}") from exc

        sep = "\t"
        set_sep = ","
        empty_field = "(empty)"
        unset_field = "-"
        fields: list[str] = []
        log_path = path.stem  # e.g., "conn", "dns", "http"

        with fh:
            for raw_line in fh:
                raw_line = raw_line.rstrip("\n")

                # Parse header directives
                if raw_line.startswith("#"):
                    if raw_line.startswith("#separator "):
                        sep_raw = raw_line.split(" ", 1)[1]
                        # Handle escape sequences like \x09
                        sep = sep_raw.encode().decode("unicode_escape")
                    elif raw_line.startswith("#set_separator "):
                        set_sep = raw_line.split(" ", 1)[1]
                    elif raw_line.startswith("#empty_field "):
                        empty_field = raw_line.split(" ", 1)[1]
                    elif raw_line.startswith("#unset_field "):
                        unset_field = raw_line.split(" ", 1)[1]
                    elif raw_line.startswith("#path "):
                        log_path = raw_line.split(" ", 1)[1].strip()
                    elif raw_line.startswith("#fields"):
                        fields = raw_line.split(sep)[1:]  # skip "#fields" token
                    continue

                if not fields:
                    self._skipped += 1
                    continue

                parts = raw_line.split(sep)
                if len(parts) != len(fields):
                    self._skipped += 1
                    continue

                row: dict[str, str] = {}
                for k, v in zip(fields, parts):
                    row[k] = v

                ts_raw = row.get("ts", "")
                ts = (
                    _zeek_ts(ts_raw)
                    if ts_raw and not _is_unset(ts_raw, unset_field, empty_field)
                    else ""
                )
                uid = row.get("uid", "")
                src_ip = row.get("id.orig_h", "")
                src_port = row.get("id.orig_p", "")
                dest_ip = row.get("id.resp_h", "")
                dest_port = row.get("id.resp_p", "")
                proto = row.get("proto", "")

                message = self._build_message(
                    log_path, row, src_ip, dest_ip, proto, unset_field, empty_field
                )

                def _g(k: str) -> str:
                    v = row.get(k, "")
                    return "" if _is_unset(v, unset_field, empty_field) else v

                event: dict = {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "zeek",
                    "timestamp": ts,
                    "timestamp_desc": "Event Time",
                    "message": message,
                    "host": {"hostname": _g("id.orig_h") or src_ip},
                    "network": {
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dest_ip,
                        "dst_port": dest_port,
                        "protocol": proto,
                        "uid": uid,
                    },
                    "zeek": {
                        "log_type": log_path,
                        **{
                            k: v
                            for k, v in row.items()
                            if not _is_unset(v, unset_field, empty_field)
                        },
                    },
                    "raw": {"line": raw_line},
                }

                # Populate standard http fields for http.log
                if log_path == "http":
                    event["http"] = {
                        "method": _g("method"),
                        "request_path": _g("uri"),
                        "protocol": _g("version"),
                        "status_code": int(_g("status_code")) if _g("status_code").isdigit() else 0,
                        "response_size": int(_g("resp_body_len"))
                        if _g("resp_body_len").isdigit()
                        else 0,
                        "referer": _g("referrer"),
                        "user_agent": _g("user_agent"),
                    }
                    # Override host.hostname with the HTTP Host header value
                    http_host = _g("host")
                    if http_host:
                        event["host"]["hostname"] = http_host

                self._parsed += 1
                yield event

    def _build_message(
        self,
        log_type: str,
        row: dict,
        src_ip: str,
        dest_ip: str,
        proto: str,
        unset: str,
        empty: str,
    ) -> str:
        def g(k: str) -> str:
            v = row.get(k, "")
            return "" if _is_unset(v, unset, empty) else v

        if log_type == "conn":
            dur = g("duration")
            state = g("conn_state")
            return (
                f"[CONN] {proto} {src_ip} → {dest_ip}:{g('id.resp_p')}  state={state}  dur={dur}s"
            )
        if log_type == "dns":
            query = g("query")
            answers = g("answers")
            rcode = g("rcode_name")
            return f"[DNS] {query}  {rcode}  → {answers[:80] if answers else ''}"
        if log_type == "http":
            method = g("method")
            host = g("host")
            uri = g("uri")
            status = g("status_code")
            return f"[HTTP] {method} {host}{uri}  → {status}"
        if log_type == "ssl":
            sni = g("server_name")
            version = g("version")
            cipher = g("cipher")
            return f"[SSL/TLS] {sni or dest_ip}  {version}  {cipher}"
        if log_type == "ssh":
            direction = g("direction")
            client = g("client")
            return f"[SSH] {direction}  {src_ip} → {dest_ip}  {client}"
        if log_type == "files":
            mime = g("mime_type")
            fname = g("filename")
            return f"[FILE] {fname or mime}  {src_ip} → {dest_ip}"
        if log_type == "notice":
            msg = g("msg")
            note = g("note")
            return f"[NOTICE] {note}  {msg[:120]}"
        if log_type == "weird":
            name = g("name")
            return f"[WEIRD] {name}  {src_ip} → {dest_ip}"
        return f"[{log_type.upper()}] {src_ip} → {dest_ip}"

    def get_stats(self) -> dict[str, Any]:
        return {"records_parsed": self._parsed, "records_skipped": self._skipped}
