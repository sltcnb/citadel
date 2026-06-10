"""
Network Connections Plugin — parses Linux ss / netstat socket state output.

Supports output from:
  - ss -tnp       (Recv-Q / Send-Q header)
  - ss -tunp      (TCP + UDP)
  - netstat -tn   (Proto / Active Internet header)

Each non-loopback ESTABLISHED connection becomes one indexed event with
network.src_ip / src_port / dst_ip / dst_port so the IOC panel, column
sorting, and Lucene field queries all work out of the box.

Typical filenames recognised automatically (no re-ingest needed):
  established_connections.log, connections.log, netstat.log, ss.log …
"""

from __future__ import annotations

import re
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

# ── Header detection ───────────────────────────────────────────────────────────

# ss -tnp  →  "Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process"
_SS_HEADER_RE = re.compile(r"^\s*Recv-Q\s+Send-Q", re.IGNORECASE)
# netstat  →  "Proto  Recv-Q  Send-Q  Local Address  Foreign Address  State"
_NETSTAT_HEADER_RE = re.compile(r"^\s*(Proto\s+Recv|Active\s+Internet)", re.IGNORECASE)

# ── Data line ─────────────────────────────────────────────────────────────────

# Matches:   recv_q  send_q  local_addr:port  peer_addr:port  [optional process]
_DATA_RE = re.compile(
    r"^\s*(\d+)\s+"  # recv_q
    r"(\d+)\s+"  # send_q
    r"(\S+)\s+"  # local  (IPv4 or [IPv6]:port)
    r"(\S+)"  # peer
    r"(?:\s+(.+))?$"  # optional process string
)

# ── Known filenames ────────────────────────────────────────────────────────────

_KNOWN_NAMES = frozenset(
    {
        "established_connections.log",
        "connections.log",
        "netstat.log",
        "netstat.txt",
        "ss_output.log",
        "ss.log",
        "network_connections.log",
        "active_connections.log",
        "open_connections.log",
        "tcp_connections.log",
        "udp_connections.log",
        "socket_stats.log",
    }
)


# ── Helpers ────────────────────────────────────────────────────────────────────


def _split_addr_port(raw: str) -> tuple[str, int]:
    """
    Parse host:port or [::ffff:host]:port → (host, port).
    Strips IPv4-mapped IPv6 prefix (::ffff:) for normalisation.
    Returns ('', 0) on failure.
    """
    raw = raw.strip()
    if raw.startswith("["):
        bracket_end = raw.rfind("]")
        if bracket_end == -1:
            return "", 0
        addr = raw[1:bracket_end]
        if addr.lower().startswith("::ffff:"):
            addr = addr[7:]
        port_part = raw[bracket_end + 2 :]
        try:
            return addr, int(port_part)
        except ValueError:
            return addr, 0
    colon = raw.rfind(":")
    if colon == -1:
        return raw, 0
    try:
        return raw[:colon], int(raw[colon + 1 :])
    except ValueError:
        return raw[:colon], 0


def _parse_ss_process(proc_str: str) -> tuple[str, int | None]:
    """
    Extract name and pid from ss process column.
    Format: users:(("nginx",pid=1234,fd=8)) or just a bare name.
    """
    if not proc_str:
        return "", None
    m_name = re.search(r'"([^"]+)"', proc_str)
    name = m_name.group(1) if m_name else proc_str.strip()
    m_pid = re.search(r"pid=(\d+)", proc_str)
    pid = int(m_pid.group(1)) if m_pid else None
    return name, pid


# ── Plugin ─────────────────────────────────────────────────────────────────────


class NetstatPlugin(BasePlugin):
    """Parses Linux ss / netstat network connection snapshots."""

    PLUGIN_NAME = "netstat"
    PLUGIN_VERSION = "1.1.0"
    DEFAULT_ARTIFACT_TYPE = "netstat"
    SUPPORTED_EXTENSIONS = [".log", ".txt"]
    SUPPORTED_MIME_TYPES = ["text/plain"]
    PLUGIN_PRIORITY = 90  # high — before generic text/log fallbacks

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(_KNOWN_NAMES)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        if file_path.name.lower() in _KNOWN_NAMES:
            return True
        # Peek at first non-empty lines for a recognisable header
        try:
            with open(file_path, errors="replace") as fh:
                for _ in range(6):
                    line = fh.readline()
                    if _SS_HEADER_RE.match(line) or _NETSTAT_HEADER_RE.match(line):
                        return True
        except OSError:
            pass
        return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open connections file: {exc}") from exc

        # Prefer file mtime as the snapshot timestamp; fall back to UTC now
        try:
            snap_ts = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        except OSError:
            snap_ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Deduplicate mirror pairs — ss reports both directions of each
        # loopback connection (A:portX ↔ A:portY appears twice reversed).
        seen: set[tuple[str, str]] = set()

        with fh:
            for raw_line in fh:
                line = raw_line.rstrip("\n")
                if not line.strip():
                    continue
                if _SS_HEADER_RE.match(line) or _NETSTAT_HEADER_RE.match(line):
                    continue

                m = _DATA_RE.match(line)
                if not m:
                    continue

                recv_q_s, send_q_s, local_raw, peer_raw, proc_raw = m.groups()
                local_ip, local_port = _split_addr_port(local_raw)
                peer_ip, peer_port = _split_addr_port(peer_raw)

                if not local_ip or not peer_ip:
                    continue

                # Deduplicate symmetric loopback pairs
                pair_key = tuple(
                    sorted(
                        [
                            f"{local_ip}:{local_port}",
                            f"{peer_ip}:{peer_port}",
                        ]
                    )
                )
                if pair_key in seen:
                    continue
                seen.add(pair_key)

                proc_name, proc_pid = _parse_ss_process(proc_raw or "")

                msg = f"ESTABLISHED {local_ip}:{local_port} → {peer_ip}:{peer_port}"
                if proc_name:
                    msg += f"  [{proc_name}]"

                event: dict[str, Any] = {
                    "timestamp": snap_ts,
                    "timestamp_desc": "Connection Snapshot",
                    "message": msg,
                    "artifact_type": "netstat",
                    "network": {
                        "src_ip": local_ip,
                        "src_port": local_port,
                        "dst_ip": peer_ip,
                        "dst_port": peer_port,
                        "protocol": "tcp",
                        "state": "ESTABLISHED",
                        "recv_q": int(recv_q_s),
                        "send_q": int(send_q_s),
                    },
                    "raw": {"line": line},
                }

                if proc_name:
                    event["process"] = {"name": proc_name}
                    if proc_pid is not None:
                        event["process"]["pid"] = proc_pid

                yield event

    def get_stats(self) -> dict[str, Any]:
        return {}
