"""
Suricata Plugin — parses Suricata EVE JSON log files.

Suricata's EVE (Extensible Event Format) outputs one JSON object per line.
This plugin handles alerts, DNS, HTTP, TLS, SSH, flow, and file-info event types.

No extra dependencies required (Python stdlib json only).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError, iso_z

# How many lines to scan when auto-detecting Suricata format
_DETECT_LINES = 10


def _looks_like_suricata(path: Path) -> bool:
    """Return True if the file looks like Suricata EVE JSON (fast heuristic)."""
    try:
        with open(path, errors="replace") as fh:
            scanned = 0
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if "event_type" in obj and (
                        "src_ip" in obj or "flow_id" in obj or "pcap_cnt" in obj
                    ):
                        return True
                except (json.JSONDecodeError, ValueError):
                    pass
                scanned += 1
                if scanned >= _DETECT_LINES:
                    break
    except OSError:
        pass
    return False


class SuricataPlugin(BasePlugin):
    """Parses Suricata EVE JSON log output."""

    PLUGIN_NAME = "suricata"
    PLUGIN_PRIORITY = 100
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "suricata"
    SUPPORTED_EXTENSIONS = [".json", ".jsonl", ".ndjson"]
    SUPPORTED_MIME_TYPES = ["application/json", "text/plain", "application/x-ndjson"]
    _KNOWN_NAMES = frozenset({"eve.json", "eve.log", "suricata.json"})

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._parsed = 0
        self._skipped = 0

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        if file_path.name.lower() in cls._KNOWN_NAMES:
            return True
        ext = file_path.suffix.lower()
        if ext not in cls.SUPPORTED_EXTENSIONS:
            return False
        return _looks_like_suricata(file_path)

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open Suricata log: {exc}") from exc

        with fh:
            for lineno, raw_line in enumerate(fh, 1):
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    obj = json.loads(raw_line)
                except (json.JSONDecodeError, ValueError):
                    self._skipped += 1
                    continue

                event = self._normalise(obj)
                if event:
                    self._parsed += 1
                    yield event
                else:
                    self._skipped += 1

    # ── helpers ───────────────────────────────────────────────────────────────

    def _normalise(self, obj: dict) -> dict | None:
        event_type = obj.get("event_type", "unknown")
        ts = iso_z(obj.get("timestamp", "")) or ""
        src_ip = obj.get("src_ip", "")
        dest_ip = obj.get("dest_ip", "")
        proto = obj.get("proto", "")
        flow_id = obj.get("flow_id", "")
        host_field = obj.get("host", "")

        # ── Build human message by event type ─────────────────────────────
        if event_type == "alert":
            alert = obj.get("alert", {})
            sig = alert.get("signature", "unknown signature")
            cat = alert.get("category", "")
            message = f"[ALERT] {sig}"
            if cat:
                message += f" — {cat}"
            message += f"  ({src_ip} → {dest_ip})"

        elif event_type == "dns":
            dns = obj.get("dns", {})
            rrname = dns.get("rrname", "")
            rtype = dns.get("rrtype", "")
            rcode = dns.get("rcode", "")
            dns_type = dns.get("type", "query")
            message = f"[DNS {dns_type.upper()}] {rrname} {rtype}"
            if rcode and rcode != "NOERROR":
                message += f" ({rcode})"
            message += f"  {src_ip} → {dest_ip}"

        elif event_type == "http":
            http = obj.get("http", {})
            method = http.get("http_method", "GET")
            hostname = http.get("hostname", dest_ip)
            url = http.get("url", "/")
            status = http.get("status", "")
            message = f"[HTTP] {method} {hostname}{url}"
            if status:
                message += f" → {status}"

        elif event_type == "tls":
            tls = obj.get("tls", {})
            sni = tls.get("sni", "")
            version = tls.get("version", "")
            subject = tls.get("subject", "")
            message = f"[TLS] {sni or dest_ip}"
            if version:
                message += f" ({version})"
            if subject:
                message += f" — {subject}"

        elif event_type == "ssh":
            ssh = obj.get("ssh", {})
            client = ssh.get("client", {})
            software = client.get("software_version", "")
            message = f"[SSH] {src_ip} → {dest_ip}"
            if software:
                message += f" — {software}"

        elif event_type == "flow":
            pkts = obj.get("flow", {}).get("pkts_toserver", "?")
            bytes_ = obj.get("flow", {}).get("bytes_toserver", "?")
            message = f"[FLOW] {proto} {src_ip} → {dest_ip}  {pkts} pkts / {bytes_} B"

        elif event_type == "fileinfo":
            fi = obj.get("fileinfo", {})
            fname = fi.get("filename", "")
            fsize = fi.get("size", "")
            message = f"[FILEINFO] {fname}"
            if fsize:
                message += f" ({fsize} B)"
            message += f"  {src_ip} → {dest_ip}"

        elif event_type == "smb":
            smb = obj.get("smb", {})
            command = smb.get("command", "")
            filename = smb.get("filename", "")
            message = f"[SMB] {command} {filename}  {src_ip} → {dest_ip}"

        elif event_type == "krb5":
            krb = obj.get("krb5", {})
            msg_type = krb.get("msg_type", "")
            cname = krb.get("cname", "")
            sname = krb.get("sname", "")
            message = f"[KRB5] {msg_type} {cname} → {sname}"

        elif event_type == "rdp":
            rdp = obj.get("rdp", {})
            ev = rdp.get("event_type", "")
            message = f"[RDP] {ev}  {src_ip} → {dest_ip}"

        else:
            message = f"[{event_type.upper()}]  {src_ip} → {dest_ip}"

        event: dict = {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": "suricata",
            "timestamp": ts,
            "timestamp_desc": "Event Time",
            "message": message,
            "host": {"hostname": host_field or src_ip},
            "network": {
                "src_ip": src_ip,
                "dst_ip": dest_ip,
                "src_port": obj.get("src_port"),
                "dst_port": obj.get("dest_port"),
                "protocol": proto,
                "flow_id": str(flow_id) if flow_id else "",
            },
            "suricata": {
                "event_type": event_type,
                "alert": obj.get("alert", {}),
                "dns": obj.get("dns", {}),
                "http": obj.get("http", {}),
                "tls": obj.get("tls", {}),
            },
            "raw": obj,
        }

        # Populate standard http fields when Suricata decoded HTTP
        if event_type == "http":
            http = obj.get("http", {})
            event["http"] = {
                "method": http.get("http_method", ""),
                "request_path": http.get("url", ""),
                "protocol": http.get("protocol", ""),
                "status_code": http.get("status", 0) or 0,
                "response_size": http.get("length", 0) or 0,
                "referer": http.get("http_refer", ""),
                "user_agent": http.get("http_user_agent", ""),
            }
            event["host"]["hostname"] = http.get("hostname", host_field or dest_ip)

        return event

    def get_stats(self) -> dict[str, Any]:
        return {"records_parsed": self._parsed, "records_skipped": self._skipped}
