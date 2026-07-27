"""
Linux Triage Plugin — structured parsing of live Linux triage collection outputs.

Handles common output files produced by fo-harvester and manual triage scripts:

  running_processes.log  → process       (ps aux: user, pid, cpu, mem, command)
  listening_ports.log    → listening_port (ss -tlnp: state, addr:port, process)
  arp_table.log          → arp_entry      (arp -a / ip neigh: ip, mac, iface)
  routing_table.log      → route_entry    (ip route / route -n: dest, gw, iface)
  logged_users.log       → logged_user    (who: user, tty, since, from_ip)
  login_history.log      → login_event    (last: user, tty, from_ip, times)
  installed_packages.log → installed_pkg  (dpkg -l / rpm -qa: name, version, arch)
  kernel_modules.log     → kernel_module  (lsmod: module, size, used_by)
  open_files.log         → open_file      (lsof -i: command, pid, user, type, name)
  environment.log        → env_variable   (env: KEY=value pairs)
  system_info.log        → system_info    (uname, hostname, distro info)
  cron_jobs.log          → cron_job       (crontab -l: schedule + command)
  scheduled_jobs.log     → cron_job

Priority 115 — above netstat (90) and syslog (100) so triage filenames are
handled by this plugin, not a generic log fallback.
"""

from __future__ import annotations

import json
import re
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

# ── Filename → handler method dispatch ────────────────────────────────────────

_FILENAME_HANDLERS: dict[str, str] = {
    "running_processes.log": "_parse_ps",
    "process_list.log": "_parse_ps",
    "processes.log": "_parse_ps",
    "ps_output.log": "_parse_ps",
    "listening_ports.log": "_parse_listening",
    "open_ports.log": "_parse_listening",
    "listening.log": "_parse_listening",
    "arp_table.log": "_parse_arp",
    "arp.log": "_parse_arp",
    "arp_cache.log": "_parse_arp",
    "routing_table.log": "_parse_routes",
    "routes.log": "_parse_routes",
    "route_table.log": "_parse_routes",
    "logged_users.log": "_parse_who",
    "who.log": "_parse_who",
    "active_sessions.log": "_parse_who",
    "login_history.log": "_parse_last",
    "last.log": "_parse_last",
    "auth_history.log": "_parse_last",
    "installed_packages.log": "_parse_packages",
    "packages.log": "_parse_packages",
    "packages.txt": "_parse_packages",
    "installed_software.log": "_parse_packages",
    "software.log": "_parse_packages",
    "kernel_modules.log": "_parse_lsmod",
    "lsmod.log": "_parse_lsmod",
    "modules.log": "_parse_lsmod",
    "open_files.log": "_parse_lsof",
    "lsof.log": "_parse_lsof",
    "network_files.log": "_parse_lsof",
    "environment.log": "_parse_env",
    "env.log": "_parse_env",
    "env_variables.log": "_parse_env",
    "environment_variables.log": "_parse_env",
    "system_info.log": "_parse_sysinfo",
    "uname.log": "_parse_sysinfo",
    "sysinfo.log": "_parse_sysinfo",
    "host_info.log": "_parse_sysinfo",
    "cron_jobs.log": "_parse_cron",
    "scheduled_jobs.log": "_parse_cron",
    "crontab.log": "_parse_cron",
    # ── Names Talon actually writes ───────────────────────────────────────────
    # Everything above follows a ".log" convention from fo-harvester-era scripts.
    # Talon (tools/talon/collect.py) names its snapshots after the command that
    # produced them and uses .txt/.json, so none of the rows above ever matched a
    # real bundle: the whole live-Linux triage set was landing on the generic
    # JSON/strings fallbacks. These entries close that gap.
    "system_triage.txt": "_parse_sysinfo",
    "ss_listening.txt": "_parse_listening",
    "dpkg_list.txt": "_parse_packages",
    "rpm_list.txt": "_parse_packages",
    "snap_list.txt": "_parse_packages",
    "flatpak_list.txt": "_parse_packages",
    "pip_list.txt": "_parse_packages",
    "pip3_list.txt": "_parse_packages",
    "gem_list.txt": "_parse_packages",
    "cargo_list.txt": "_parse_packages",
    "npm_global.txt": "_parse_packages",
    "recent_installs.txt": "_parse_dpkg_log",
    "recent_rpm_installs.txt": "_parse_rpm_installs",
    # /proc snapshots — Talon flattens the path, so /proc/net/arp → proc/net_arp.
    "net_arp": "_parse_proc_arp",
    "proc_net_arp": "_parse_proc_arp",
    "modules": "_parse_lsmod",
    "proc_modules": "_parse_lsmod",
    # /proc/net/{tcp,udp,tcp6,udp6} — the kernel socket table. Talon collects it
    # under network_config/proc_net/<proto>, so the name is the bare protocol.
    "tcp": "_parse_proc_net_sock",
    "tcp6": "_parse_proc_net_sock",
    "udp": "_parse_proc_net_sock",
    "udp6": "_parse_proc_net_sock",
    "proc_net_tcp": "_parse_proc_net_sock",
    "proc_net_udp": "_parse_proc_net_sock",
    # `ip -j` JSON snapshots.
    "ip_neigh.json": "_parse_ip_json_neigh",
    "ip_route.json": "_parse_ip_json_route",
    "ip_addr.json": "_parse_ip_json_addr",
    # Login history + systemd unit inventories.
    "lastlog.txt": "_parse_lastlog",
    "enabled_services.txt": "_parse_enabled_units",
    "enabled_timers.txt": "_parse_enabled_units",
}

# ── Regex patterns ─────────────────────────────────────────────────────────────

# ps aux header — "USER  PID  %CPU  %MEM  VSZ  RSS  TTY  STAT  START  TIME  COMMAND"
_PS_HEADER_RE = re.compile(r"^\s*USER\s+PID\s+%CPU", re.IGNORECASE)
# ps aux data line
_PS_RE = re.compile(
    r"^(\S+)\s+"  # user
    r"(\d+)\s+"  # pid
    r"([\d.]+)\s+"  # %cpu
    r"([\d.]+)\s+"  # %mem
    r"(\d+)\s+"  # vsz
    r"(\d+)\s+"  # rss
    r"(\S+)\s+"  # tty
    r"(\S+)\s+"  # stat
    r"(\S+)\s+"  # start
    r"(\S+)\s+"  # time
    r"(.+)$"  # command
)

# ss -tlnp listening line (has STATE column before Recv-Q)
_LISTEN_RE = re.compile(
    r"^(LISTEN|UNCONN|ESTAB|CLOSE-WAIT|TIME-WAIT)\s+"
    r"(\d+)\s+"  # recv_q
    r"(\d+)\s+"  # send_q
    r"(\S+)\s+"  # local addr:port
    r"(\S+)"  # peer addr:port (usually *:*)
    r"(?:\s+(.+))?$",  # optional process
    re.IGNORECASE,
)
_LISTEN_HEADER_RE = re.compile(r"^\s*State\s+Recv-Q", re.IGNORECASE)

# arp -a:  "gateway (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
_ARP_A_RE = re.compile(r"^(\S+)\s+\((\S+)\)\s+at\s+(\S+)\s+\[(\w+)\]\s+on\s+(\S+)", re.IGNORECASE)
# ip neigh: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
_IP_NEIGH_RE = re.compile(r"^(\S+)\s+dev\s+(\S+)(?:\s+lladdr\s+(\S+))?\s+(\S+)$", re.IGNORECASE)

# ip route: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
_IP_ROUTE_RE = re.compile(
    r"^(\S+)(?:\s+via\s+(\S+))?(?:\s+dev\s+(\S+))?(?:\s+proto\s+(\S+))?"
    r"(?:\s+metric\s+(\d+))?(?:\s+src\s+(\S+))?"
)
# route -n: "0.0.0.0  192.168.1.1  0.0.0.0  UG  100  0  0  eth0"
_ROUTE_N_RE = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+)\s+"
    r"(\d+\.\d+\.\d+\.\d+)\s+"
    r"(\d+\.\d+\.\d+\.\d+)\s+"
    r"(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)"
)
_ROUTE_HEADER_RE = re.compile(r"^\s*(Kernel IP routing|Destination\s+Gateway)", re.IGNORECASE)

# who: "user   pts/0  2024-01-01 12:00 (192.168.1.100)"
_WHO_RE = re.compile(
    r"^(\S+)\s+"  # user
    r"(\S+)\s+"  # tty
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})"  # date time
    r"(?:\s+\((.+)\))?"  # optional (from)
)

# last: "user  pts/0  192.168.1.100  Mon Jan  1 12:00   still logged in"
_LAST_RE = re.compile(
    r"^(\S+)\s+"  # user
    r"(\S+)\s+"  # tty/system
    r"(\S+)\s+"  # from ip or blank
    r"(\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2})"  # date
    r"(?:\s+-\s+(\S+\s+\S+)\s+\(([^)]+)\))?"  # optional logout + duration
    r"(?:\s+(still logged in))?"
)

# dpkg -l:  "ii  openssh-server  1:8.9p1-3  amd64  Secure shell server"
_DPKG_RE = re.compile(r"^(\S{2,3})\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$")
_DPKG_HDR = re.compile(r"^\+\+\+|^Desired=|^\|/")
# rpm -qa:  "openssh-server-8.7p1-34.el9.x86_64"
_RPM_RE = re.compile(r"^([\w.+-]+)-([^-]+-[^.]+)\.([^.]+)$")

# /var/log/dpkg.log:
#   "2026-01-15 10:00:01 install netcat-openbsd:amd64 <none> 1.206-1"
#   "2026-01-15 10:00:04 upgrade curl:amd64 7.88.1-10 7.88.1-10+deb12u5"
_DPKG_LOG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+"
    r"(install|upgrade|remove|purge|configure|trigproc)\s+"
    r"(\S+)\s+(\S+)\s+(\S+)$"
)

# /proc/net/tcp state column (net/tcp_states.h).
_PROC_TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def _join_state(state: Any) -> str:
    """`ip -j neigh` reports state as a list; older/other forms as a bare string."""
    if isinstance(state, list):
        return " ".join(str(s) for s in state)
    return str(state) if state else ""


def _decode_proc_addr(field: str) -> tuple[str | None, int | None]:
    """Decode a /proc/net "ADDRESS:PORT" hex pair into (dotted/colon ip, port).

    The address is host-byte-order hex in 32-bit groups — little-endian on every
    architecture Linux forensics touches — while the port is big-endian. Getting
    this backwards silently yields plausible-looking wrong IPs, so each 4-byte
    group is reversed explicitly.
    """
    addr_hex, _, port_hex = field.partition(":")
    try:
        port = int(port_hex, 16)
    except ValueError:
        return None, None

    if len(addr_hex) == 8:  # IPv4
        try:
            octets = [int(addr_hex[i : i + 2], 16) for i in range(0, 8, 2)]
        except ValueError:
            return None, None
        return ".".join(str(o) for o in reversed(octets)), port

    if len(addr_hex) == 32:  # IPv6 — four little-endian 32-bit words
        try:
            words = [addr_hex[i : i + 8] for i in range(0, 32, 8)]
            raw = b"".join(bytes.fromhex(w)[::-1] for w in words)
        except ValueError:
            return None, None
        groups = [f"{raw[i] << 8 | raw[i + 1]:x}" for i in range(0, 16, 2)]
        return ":".join(groups), port

    return None, None

# lsmod:  "nfnetlink  20480  4 nft_compat,nf_tables"
_LSMOD_RE = re.compile(r"^(\S+)\s+(\d+)\s+(\d+)\s*(.*)")
_LSMOD_HDR = re.compile(r"^\s*Module\s+Size\s+Used by", re.IGNORECASE)

# lsof -i: "sshd  1234  root  3u  IPv4  12345  0t0  TCP *:22 (LISTEN)"
_LSOF_RE = re.compile(
    r"^(\S+)\s+"  # command
    r"(\d+)\s+"  # pid
    r"(\S+)\s+"  # user
    r"(\S+)\s+"  # fd
    r"(\S+)\s+"  # type
    r"(\S+)\s+"  # device
    r"(\S+)\s+"  # size
    r"(\S+)\s+"  # node
    r"(.+)$"  # name (TCP 1.2.3.4:80->5.6.7.8:12345 (ESTABLISHED))
)
_LSOF_HDR = re.compile(r"^\s*COMMAND\s+PID", re.IGNORECASE)

# cron: "# comment" or "*/5 * * * * /usr/bin/something" or "@reboot cmd"
_CRON_RE = re.compile(r"^(@\w+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.+)$")


def _now_ts() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _file_mtime(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return _now_ts()


def _split_addr_port(raw: str) -> tuple[str, int]:
    """Parse host:port or [IPv6]:port → (host, port)."""
    raw = raw.strip()
    if raw in ("*", "0.0.0.0:*", "[::]:*", "*:*"):
        return "*", 0
    if raw.startswith("["):
        bracket_end = raw.rfind("]")
        if bracket_end == -1:
            return raw, 0
        addr = raw[1:bracket_end]
        if addr.lower().startswith("::ffff:"):
            addr = addr[7:]
        try:
            return addr, int(raw[bracket_end + 2 :])
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
    if not proc_str:
        return "", None
    m_name = re.search(r'"([^"]+)"', proc_str)
    name = m_name.group(1) if m_name else proc_str.strip()
    m_pid = re.search(r"pid=(\d+)", proc_str)
    pid = int(m_pid.group(1)) if m_pid else None
    return name, pid


# ── Main plugin ────────────────────────────────────────────────────────────────


class LinuxTriagePlugin(BasePlugin):
    """Parses Linux live triage collection outputs."""

    PLUGIN_NAME = "linux_triage"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "linux_triage"
    SUPPORTED_EXTENSIONS = [".log", ".txt"]
    SUPPORTED_MIME_TYPES = ["text/plain", "text/x-linux-triage"]
    PLUGIN_PRIORITY = 115

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(_FILENAME_HANDLERS.keys())

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        return file_path.name.lower() in _FILENAME_HANDLERS

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        handler = _FILENAME_HANDLERS.get(path.name.lower())
        if not handler:
            return
        method = getattr(self, handler, None)
        if method is None:
            return
        snap_ts = _file_mtime(path)
        try:
            with open(path, errors="replace") as fh:
                lines = fh.readlines()
        except OSError as exc:
            raise PluginFatalError(f"Cannot open {path.name}: {exc}") from exc
        yield from method(lines, snap_ts)

    # ── ps aux ────────────────────────────────────────────────────────────────

    def _parse_ps(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip() or _PS_HEADER_RE.match(line):
                continue
            m = _PS_RE.match(line)
            if not m:
                continue
            user, pid, cpu, mem, vsz, rss, tty, stat, start, time_, cmd = m.groups()
            exe = cmd.split()[0] if cmd else ""
            yield {
                "timestamp": ts,
                "timestamp_desc": "Process Snapshot",
                "artifact_type": "process",
                "message": f"{exe}  (pid={pid} user={user} cpu={cpu}% mem={mem}%)",
                "process": {
                    "name": exe.split("/")[-1] if exe else cmd,
                    "path": exe if exe.startswith("/") else "",
                    "command_line": cmd,
                    "pid": int(pid),
                },
                "user": {"name": user},
                "host": {},
                "network": {},
                "linux_process": {
                    "cpu_pct": float(cpu),
                    "mem_pct": float(mem),
                    "vsz_kb": int(vsz),
                    "rss_kb": int(rss),
                    "tty": tty,
                    "stat": stat,
                    "start": start,
                    "time": time_,
                },
            }

    # ── ss -tlnp (listening ports) ────────────────────────────────────────────

    def _parse_listening(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip() or _LISTEN_HEADER_RE.match(line):
                continue
            m = _LISTEN_RE.match(line)
            if not m:
                continue
            state, recv_q, send_q, local_raw, peer_raw, proc_raw = m.groups()
            local_ip, local_port = _split_addr_port(local_raw)
            proc_name, proc_pid = _parse_ss_process(proc_raw or "")
            msg = f"{state} {local_ip}:{local_port}"
            if proc_name:
                msg += f"  [{proc_name}]"
            event: dict[str, Any] = {
                "timestamp": ts,
                "timestamp_desc": "Port Snapshot",
                "artifact_type": "listening_port",
                "message": msg,
                "network": {
                    "src_ip": local_ip,
                    "src_port": local_port,
                    "protocol": "tcp",
                    "state": state.upper(),
                },
            }
            if proc_name:
                event["process"] = {"name": proc_name}
                if proc_pid is not None:
                    event["process"]["pid"] = proc_pid
            yield event

    # ── arp ───────────────────────────────────────────────────────────────────

    def _parse_arp(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            # arp -a
            m = _ARP_A_RE.match(line)
            if m:
                hostname, ip, mac, hw_type, iface = m.groups()
                yield {
                    "timestamp": ts,
                    "timestamp_desc": "ARP Snapshot",
                    "artifact_type": "arp_entry",
                    "message": f"{ip} → {mac}  [{iface}]",
                    "network": {"src_ip": ip},
                    "arp": {
                        "ip": ip,
                        "mac": mac.lower(),
                        "hostname": hostname if hostname != "?" else "",
                        "hw_type": hw_type,
                        "iface": iface,
                    },
                }
                continue
            # ip neigh
            m2 = _IP_NEIGH_RE.match(line)
            if m2:
                ip, iface, mac, state = m2.groups()
                yield {
                    "timestamp": ts,
                    "timestamp_desc": "ARP Snapshot",
                    "artifact_type": "arp_entry",
                    "message": f"{ip} → {mac or '?'}  [{iface}]  {state}",
                    "network": {"src_ip": ip},
                    "arp": {
                        "ip": ip,
                        "mac": (mac or "").lower(),
                        "iface": iface,
                        "state": state,
                    },
                }

    # ── routing table ─────────────────────────────────────────────────────────

    def _parse_routes(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip() or _ROUTE_HEADER_RE.match(line):
                continue
            # route -n
            m = _ROUTE_N_RE.match(line)
            if m:
                dest, gw, mask, flags, metric, _, _, iface = m.groups()
                yield {
                    "timestamp": ts,
                    "timestamp_desc": "Route Snapshot",
                    "artifact_type": "route_entry",
                    "message": f"{dest}/{mask} via {gw}  [{iface}]",
                    "network": {"dst_ip": dest},
                    "route": {
                        "destination": dest,
                        "gateway": gw,
                        "netmask": mask,
                        "flags": flags,
                        "metric": int(metric),
                        "iface": iface,
                    },
                }
                continue
            # ip route
            m2 = _IP_ROUTE_RE.match(line)
            if m2:
                dest, gw, iface, proto, metric, src = m2.groups()
                if not dest or dest.startswith("#"):
                    continue
                yield {
                    "timestamp": ts,
                    "timestamp_desc": "Route Snapshot",
                    "artifact_type": "route_entry",
                    "message": f"{dest}"
                    + (f" via {gw}" if gw else "")
                    + (f"  [{iface}]" if iface else ""),
                    "network": {"dst_ip": dest},
                    "route": {
                        "destination": dest,
                        "gateway": gw or "",
                        "iface": iface or "",
                        "proto": proto or "",
                        "metric": int(metric) if metric else 0,
                        "src": src or "",
                    },
                }

    # ── who ───────────────────────────────────────────────────────────────────

    def _parse_who(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            m = _WHO_RE.match(line)
            if not m:
                continue
            user, tty, when, from_ip = m.groups()
            yield {
                "timestamp": ts,
                "timestamp_desc": "Login Snapshot",
                "artifact_type": "logged_user",
                "message": f"{user}  on {tty}" + (f"  from {from_ip}" if from_ip else ""),
                "user": {"name": user},
                "network": {"src_ip": from_ip or ""},
                "session": {
                    "user": user,
                    "tty": tty,
                    "since": when,
                    "from_ip": from_ip or "",
                },
            }

    # ── last ──────────────────────────────────────────────────────────────────

    def _parse_last(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            # Skip the "wtmp begins" footer
            if "wtmp begins" in line or "btmp begins" in line:
                continue
            m = _LAST_RE.match(line)
            if not m:
                continue
            user, tty, from_ip, login_time, logout_time, duration, still_in = m.groups()
            status = "active" if still_in else ("logged out" if logout_time else "unknown")
            yield {
                "timestamp": ts,
                "timestamp_desc": "Login Event",
                "artifact_type": "login_event",
                "message": f"{user}  {tty}  {from_ip or 'local'}  {login_time}  [{status}]",
                "user": {"name": user},
                "network": {"src_ip": from_ip if from_ip and from_ip not in ("", "-") else ""},
                "login": {
                    "user": user,
                    "tty": tty,
                    "from_ip": from_ip or "",
                    "login_time": login_time,
                    "logout_time": logout_time or "",
                    "duration": duration or "",
                    "status": status,
                },
            }

    # ── dpkg -l / rpm -qa ─────────────────────────────────────────────────────

    def _parse_packages(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip() or _DPKG_HDR.match(line):
                continue
            # dpkg -l format
            m_dpkg = _DPKG_RE.match(line)
            if m_dpkg and not line.strip().startswith("+-"):
                status, name, version, arch, description = m_dpkg.groups()
                if status in ("ii", "rc", "pu", "iU", "iF", "iH") or re.match(r"[a-z]{2}", status):
                    yield {
                        "timestamp": ts,
                        "timestamp_desc": "Package Snapshot",
                        "artifact_type": "installed_pkg",
                        "message": f"{name} {version} [{arch}]  {description[:80]}",
                        "package": {
                            "name": name,
                            "version": version,
                            "arch": arch,
                            "description": description,
                            "status": status,
                            "manager": "dpkg",
                        },
                    }
                    continue
            # rpm -qa: name-version-release.arch
            m_rpm = _RPM_RE.match(line.strip())
            if m_rpm:
                name, ver_rel, arch = m_rpm.groups()
                yield {
                    "timestamp": ts,
                    "timestamp_desc": "Package Snapshot",
                    "artifact_type": "installed_pkg",
                    "message": f"{name} {ver_rel} [{arch}]",
                    "package": {
                        "name": name,
                        "version": ver_rel,
                        "arch": arch,
                        "manager": "rpm",
                    },
                }

    # ── lsmod ─────────────────────────────────────────────────────────────────

    def _parse_lsmod(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip() or _LSMOD_HDR.match(line):
                continue
            m = _LSMOD_RE.match(line)
            if not m:
                continue
            module, size, used_count, used_by = m.groups()
            deps = [d.strip() for d in used_by.split(",") if d.strip()]
            yield {
                "timestamp": ts,
                "timestamp_desc": "Module Snapshot",
                "artifact_type": "kernel_module",
                "message": f"{module}  ({size} bytes, used by {used_count})",
                "kernel_module": {
                    "name": module,
                    "size_bytes": int(size),
                    "used_by": deps,
                    "use_count": int(used_count),
                },
            }

    # ── lsof -i ───────────────────────────────────────────────────────────────

    def _parse_lsof(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip() or _LSOF_HDR.match(line):
                continue
            m = _LSOF_RE.match(line)
            if not m:
                continue
            cmd, pid, user, fd, ftype, device, size, node, name = m.groups()
            yield {
                "timestamp": ts,
                "timestamp_desc": "Open Files Snapshot",
                "artifact_type": "open_file",
                "message": f"{cmd} (pid={pid})  {name}",
                "process": {"name": cmd, "pid": int(pid)},
                "user": {"name": user},
                "open_file": {
                    "command": cmd,
                    "pid": int(pid),
                    "user": user,
                    "fd": fd,
                    "type": ftype,
                    "node": node,
                    "name": name,
                },
            }

    # ── env ───────────────────────────────────────────────────────────────────

    def _parse_env(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        # Skip obviously sensitive variables
        _SKIP = frozenset({"LS_COLORS", "TERM_PROGRAM_VERSION"})
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if not key or key in _SKIP:
                continue
            yield {
                "timestamp": ts,
                "timestamp_desc": "Environment Snapshot",
                "artifact_type": "env_variable",
                "message": f"{key}={value[:200]}",
                "env": {
                    "key": key,
                    "value": value,
                },
            }

    # ── system_info (uname / freeform) ────────────────────────────────────────

    def _parse_sysinfo(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        full_text = "\n".join(l.rstrip("\n") for l in lines if l.strip())
        if not full_text:
            return
        # Try to extract kernel + hostname from uname -a line
        uname_m = re.search(
            r"Linux\s+(\S+)\s+"  # hostname
            r"(\S+)\s+"  # kernel version
            r"#(\S+)",  # build
            full_text,
        )
        hostname = uname_m.group(1) if uname_m else ""
        kernel = uname_m.group(2) if uname_m else ""

        yield {
            "timestamp": ts,
            "timestamp_desc": "System Info",
            "artifact_type": "system_info",
            "message": full_text[:500],
            "host": {"hostname": hostname} if hostname else {},
            "system_info": {
                "raw": full_text[:2000],
                "kernel": kernel,
                "hostname": hostname,
            },
        }

    # ── crontab ───────────────────────────────────────────────────────────────

    def _parse_cron(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        for line in lines:
            line = line.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = _CRON_RE.match(stripped)
            if not m:
                continue
            schedule, command = m.groups()
            yield {
                "timestamp": ts,
                "timestamp_desc": "Cron Job Snapshot",
                "artifact_type": "cron_job",
                "message": f"{schedule}  →  {command[:200]}",
                "cron": {
                    "schedule": schedule,
                    "command": command,
                },
            }

    # ── /proc/net/arp ─────────────────────────────────────────────────────────

    def _parse_proc_arp(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        """/proc/net/arp — the kernel's own ARP cache, not `arp -a` output.

        Format differs from both existing ARP shapes (no parentheses, no `dev`
        keyword), so it needs its own reader:

            IP address  HW type  Flags  HW address         Mask  Device
            10.0.0.9    0x1      0x2    de:ad:be:ef:00:01  *     eth0
        """
        for line in lines:
            parts = line.split()
            if len(parts) < 6 or parts[0].lower().startswith("ip"):
                continue  # header
            ip, hw_type, flags, mac, mask, iface = parts[:6]
            # Incomplete entries (mac all-zero) mean an ARP probe went unanswered
            # — useful as a scan signal, so they are kept and flagged.
            incomplete = mac in ("00:00:00:00:00:00", "<incomplete>")
            yield {
                "timestamp": ts,
                "timestamp_desc": "ARP Cache Snapshot",
                "artifact_type": "arp_entry",
                "message": f"{ip} → {mac}  [{iface}]" + ("  (incomplete)" if incomplete else ""),
                "network": {"src_ip": ip},
                "arp": {
                    "ip": ip,
                    "mac": mac.lower(),
                    "iface": iface,
                    "hw_type": hw_type,
                    "flags": flags,
                    "mask": mask,
                    "incomplete": incomplete,
                },
                "raw": {"line": line.rstrip("\n")},
            }

    # ── ip -j addr / route / neigh (JSON) ─────────────────────────────────────

    def _load_json(self, lines: list[str]) -> list[dict]:
        """Decode an `ip -j` document; return [] rather than raising on garbage."""
        try:
            doc = json.loads("".join(lines))
        except (json.JSONDecodeError, ValueError):
            return []
        if isinstance(doc, dict):
            return [doc]
        return [d for d in doc if isinstance(d, dict)] if isinstance(doc, list) else []

    def _parse_ip_json_neigh(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        for entry in self._load_json(lines):
            ip = entry.get("dst", "")
            mac = str(entry.get("lladdr", "")).lower()
            if not ip:
                continue
            yield {
                "timestamp": ts,
                "timestamp_desc": "ARP Snapshot",
                "artifact_type": "arp_entry",
                "message": f"{ip} → {mac or '(unresolved)'}  [{entry.get('dev', '')}]",
                "network": {"src_ip": ip},
                "arp": {
                    "ip": ip,
                    "mac": mac,
                    "iface": entry.get("dev", ""),
                    "state": _join_state(entry.get("state")),
                },
                "raw": entry,
            }

    def _parse_ip_json_route(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        for entry in self._load_json(lines):
            dest = entry.get("dst", "")
            if not dest:
                continue
            gateway = entry.get("gateway", "")
            yield {
                "timestamp": ts,
                "timestamp_desc": "Route Snapshot",
                "artifact_type": "route_entry",
                "message": (
                    f"{dest}" + (f" via {gateway}" if gateway else "")
                    + f" dev {entry.get('dev', '')}"
                ),
                "route": {
                    "destination": dest,
                    "gateway": gateway,
                    "iface": entry.get("dev", ""),
                    "protocol": entry.get("protocol", ""),
                    "metric": entry.get("metric"),
                    "source": entry.get("prefsrc", ""),
                },
                "raw": entry,
            }

    def _parse_ip_json_addr(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        """One event per configured address — establishes what the host *was*.

        Host IP attribution is the anchor for correlating this bundle against
        network telemetry, so each address is emitted with its interface and
        link state rather than summarised.
        """
        for entry in self._load_json(lines):
            iface = entry.get("ifname", "")
            for addr in entry.get("addr_info") or []:
                if not isinstance(addr, dict) or not addr.get("local"):
                    continue
                ip = addr["local"]
                yield {
                    "timestamp": ts,
                    "timestamp_desc": "Interface Address Snapshot",
                    "artifact_type": "interface_address",
                    "message": (
                        f"{iface}: {ip}/{addr.get('prefixlen', '')} "
                        f"({addr.get('family', '')}, {entry.get('operstate', '')})"
                    ),
                    "network": {"src_ip": ip},
                    "interface": {
                        "name": iface,
                        "address": ip,
                        "prefix_length": addr.get("prefixlen"),
                        "family": addr.get("family", ""),
                        "mac": str(entry.get("address", "")).lower(),
                        "operstate": entry.get("operstate", ""),
                        "mtu": entry.get("mtu"),
                        "scope": addr.get("scope", ""),
                    },
                    "raw": {
                        "link": {k: v for k, v in entry.items() if k != "addr_info"},
                        "addr": addr,
                    },
                }

    # ── lastlog ───────────────────────────────────────────────────────────────

    def _parse_lastlog(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        """`lastlog` output — last login per account, including never-logged-in.

        Distinct from `last` (which the existing _parse_last handles): lastlog is
        one row per account, so it answers "which accounts have ever been used",
        which is how a dormant service account suddenly logging in gets noticed.
        """
        for line in lines:
            line = line.rstrip("\n")
            parts = line.split()
            if not parts or parts[0].lower() == "username":
                continue
            username = parts[0]
            rest = line[len(username):].strip()
            if rest.lower().startswith("**never logged in**"):
                yield {
                    "timestamp": ts,
                    "timestamp_desc": "Account Never Used",
                    "artifact_type": "login_event",
                    "message": f"{username}: never logged in",
                    "user": {"name": username},
                    "login": {"username": username, "never_logged_in": True},
                    "raw": {"line": line},
                }
                continue
            yield {
                "timestamp": ts,
                "timestamp_desc": "Last Login Snapshot",
                "artifact_type": "login_event",
                "message": f"{username}: last login {rest}",
                "user": {"name": username},
                "login": {"username": username, "never_logged_in": False, "detail": rest},
                "raw": {"line": line},
            }

    # ── systemctl list-unit-files --state=enabled ─────────────────────────────

    def _parse_enabled_units(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        """Enabled systemd units — the persistence inventory of a live host.

        A unit enabled but absent from the on-disk unit files Talon also collects
        is a strong tampering signal, so the pair is worth having in one timeline.
        """
        for line in lines:
            line = line.rstrip("\n")
            parts = line.split()
            if len(parts) < 2 or not parts[0].count("."):
                continue
            if parts[0].lower() in ("unit", "unit_file", "unit-file"):
                continue
            unit, state = parts[0], parts[1]
            yield {
                "timestamp": ts,
                "timestamp_desc": "Enabled Unit Snapshot",
                "artifact_type": "systemd_unit",
                "message": f"systemd unit {unit} is {state}",
                "systemd_unit": {
                    "name": unit,
                    "unit_type": unit.rsplit(".", 1)[-1],
                    "state": state,
                    "enabled": state.lower() in ("enabled", "enabled-runtime", "static"),
                },
                "raw": {"line": line},
            }

    # ── dpkg.log / rpm install history ────────────────────────────────────────

    def _parse_dpkg_log(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        """Grepped /var/log/dpkg.log lines — timestamped package installs.

        Unlike the `dpkg -l` inventory these carry a real timestamp, so they
        place "attacker installed nmap" at a point on the timeline rather than
        just asserting it is present.
        """
        for line in lines:
            line = line.rstrip("\n")
            m = _DPKG_LOG_RE.match(line.strip())
            if not m:
                continue
            date, time_, action, pkg, old_ver, new_ver = m.groups()
            yield {
                "timestamp": f"{date}T{time_}Z",
                "timestamp_desc": f"Package {action.title()}",
                "artifact_type": "package_event",
                "message": f"{action} {pkg} {old_ver} → {new_ver}".replace(" <none>", ""),
                "package": {
                    "name": pkg.split(":")[0],
                    "arch": pkg.split(":")[1] if ":" in pkg else "",
                    "action": action,
                    "version_before": "" if old_ver == "<none>" else old_ver,
                    "version": new_ver,
                    "manager": "dpkg",
                },
                "raw": {"line": line},
            }

    def _parse_rpm_installs(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        """`rpm -qa --qf '%{INSTALLTIME:date} %{NAME}'` — install time per package."""
        for line in lines:
            line = line.rstrip("\n").strip()
            if not line:
                continue
            # "Mon 15 Jan 2026 10:00:01 AM UTC netcat" — split the trailing name.
            parts = line.rsplit(None, 1)
            if len(parts) != 2:
                continue
            when, pkg = parts
            yield {
                "timestamp": ts,
                "timestamp_desc": "Package Install",
                "artifact_type": "package_event",
                "message": f"installed {pkg} at {when}",
                "package": {"name": pkg, "action": "install", "manager": "rpm"},
                "raw": {"line": line, "install_time": when},
            }

    # ── /proc/net/{tcp,udp,tcp6,udp6} ─────────────────────────────────────────

    def _parse_proc_net_sock(self, lines: list[str], ts: str) -> Generator[dict, None, None]:
        """Kernel socket table — the ground truth `ss`/`netstat` are rendered from.

        Worth reading directly: a rootkit that hides connections usually hooks
        the userland tools, not /proc, so an ESTABLISHED socket present here but
        absent from the collected `ss` output is itself the finding.

        Addresses are little-endian hex, ports big-endian hex:

            sl  local_address rem_address   st tx_queue:rx_queue ... uid ... inode
             0: 0500000A:AD31 0900000A:1160 01 00000000:00000000     0      12345
        """
        for line in lines:
            parts = line.split()
            if len(parts) < 10 or not parts[0].rstrip(":").isdigit():
                continue  # header or truncated row
            local, remote, state_hex = parts[1], parts[2], parts[3]
            local_ip, local_port = _decode_proc_addr(local)
            remote_ip, remote_port = _decode_proc_addr(remote)
            if local_ip is None:
                continue
            state = _PROC_TCP_STATES.get(state_hex.upper(), f"UNKNOWN({state_hex})")
            uid = parts[7] if len(parts) > 7 else ""
            inode = parts[9] if len(parts) > 9 else ""
            listening = state == "LISTEN"
            yield {
                "timestamp": ts,
                "timestamp_desc": "Socket Table Snapshot",
                "artifact_type": "listening_port" if listening else "network_conn",
                "message": (
                    f"{state} {local_ip}:{local_port}"
                    + ("" if listening else f" → {remote_ip}:{remote_port}")
                    + f"  uid={uid}"
                ),
                "network": {
                    "src_ip": local_ip,
                    "src_port": local_port,
                    "dest_ip": None if listening else remote_ip,
                    "dest_port": None if listening else remote_port,
                },
                "socket": {
                    "state": state,
                    "local_address": local_ip,
                    "local_port": local_port,
                    "remote_address": remote_ip,
                    "remote_port": remote_port,
                    "uid": uid,
                    "inode": inode,
                    "listening": listening,
                },
                "user": {"id": uid} if uid else {},
                "raw": {"line": line.rstrip("\n")},
            }
