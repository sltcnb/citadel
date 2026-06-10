"""
Windows Triage Plugin — structured parsing of live Windows triage output files.

Handles fo-harvester triage output:
  systeminfo.txt     → system_info  (hostname, OS version, install date, hotfixes)
  netstat.txt        → network_conn (protocol, local addr:port, remote addr:port, state, PID)
  tasklist.txt       → process      (name, PID, session, memory)
  services.txt       → service      (name, state, start type, binary path)
  installed_software.txt → installed_software (name, version, publisher, install date)
  startup_items.txt  → startup_item (name, location, command)

Also handles:
  pfirewall.log      → firewall_log (action, protocol, src_ip:port, dst_ip:port)
  IIS W3C logs (u_ex*.log) → iis_access_log (datetime, method, uri, status, client_ip)

Priority 115 — above syslog (100) and shell_history (110).
"""

from __future__ import annotations

import re
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

# Exact filenames (lowercase) and their handlers
_FILENAME_HANDLERS: dict[str, str] = {
    "systeminfo.txt": "_parse_systeminfo",
    "netstat.txt": "_parse_netstat",
    "tasklist.txt": "_parse_tasklist",
    "services.txt": "_parse_services",
    "installed_software.txt": "_parse_installed_software",
    "startup_items.txt": "_parse_startup_items",
    "pfirewall.log": "_parse_firewall_log",
}

# IIS W3C log file pattern: u_ex<date>.log or u_in<date>.log
_IIS_NAME_RE = re.compile(r"^u_(ex|in)\d+\.log$", re.IGNORECASE)

# Windows Firewall log line:
# "2024-01-01 12:00:00 ALLOW TCP 10.0.0.1 8.8.8.8 54321 53 ..."
_FW_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(ALLOW|DROP|DROP-ICMP)\s+"
    r"(\S+)\s+"  # protocol
    r"(\S+)\s+"  # src_ip
    r"(\S+)\s+"  # dst_ip
    r"(\S+)\s+"  # src_port
    r"(\S+)"  # dst_port
)

# netstat line patterns
# "  TCP    0.0.0.0:135   0.0.0.0:0   LISTENING   424"
_NETSTAT_RE = re.compile(
    r"^\s*(TCP|UDP)\s+"
    r"(\S+)\s+"  # local addr:port
    r"(\S+)\s+"  # remote addr:port
    r"(\S+)"  # state or PID (UDP has no state)
    r"(?:\s+(\d+))?",  # PID (optional for UDP)
    re.IGNORECASE,
)

# tasklist line: "  chrome.exe    1234 Console    1    123,456 K"
_TASKLIST_RE = re.compile(
    r"^(.+?)\s{2,}"  # image name (greedy until 2+ spaces)
    r"(\d+)\s+"  # PID
    r"(\S+)\s+"  # session
    r"(\d+)\s+"  # session #
    r"([\d,]+)\s*K",  # memory in K
)

# IIS W3C timestamp: "2024-01-01 12:00:00"
_IIS_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})\s+(.*)")


def _file_mtime_iso(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()
    except OSError:
        return datetime.now(UTC).isoformat()


class WindowsTriagePlugin(BasePlugin):
    """Parses Windows live triage output and Windows log files."""

    PLUGIN_NAME = "windows_triage"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "triage"
    SUPPORTED_EXTENSIONS = []
    SUPPORTED_MIME_TYPES = ["text/x-windows-triage"]
    PLUGIN_PRIORITY = 115

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        if mime_type == "text/x-windows-triage":
            return True
        name = file_path.name.lower()
        if name in _FILENAME_HANDLERS:
            return True
        if _IIS_NAME_RE.match(file_path.name):
            return True
        return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        name = path.name.lower()
        self._snap_ts = _file_mtime_iso(path)

        handler_name = _FILENAME_HANDLERS.get(name)
        if handler_name:
            yield from getattr(self, handler_name)(path)
            return

        if _IIS_NAME_RE.match(path.name):
            yield from self._parse_iis_log(path)
            return

    # ── File reader ───────────────────────────────────────────────────────────

    def _lines(self, path: Path) -> list[str]:
        try:
            return path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            raise PluginFatalError(f"Cannot read {path.name}: {exc}") from exc

    # ── systeminfo.txt ────────────────────────────────────────────────────────

    def _parse_systeminfo(self, path: Path) -> Generator[dict, None, None]:
        """Parses 'key:                    value' format of systeminfo output."""
        info: dict[str, str] = {}
        for line in self._lines(path):
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if key and value:
                info[key] = value

        hostname = info.get("Host Name", info.get("Computer Name", ""))
        os_name = info.get("OS Name", "")
        os_ver = info.get("OS Version", "")
        install_date = info.get("Original Install Date", "")
        last_boot = info.get("System Boot Time", "")

        yield {
            "timestamp": self._snap_ts,
            "timestamp_desc": "System Info (Collection Time)",
            "message": f"System: {hostname}  OS: {os_name} {os_ver}",
            "artifact_type": "system_info",
            "system_info": {
                "hostname": hostname,
                "os_name": os_name,
                "os_version": os_ver,
                "install_date": install_date,
                "last_boot": last_boot,
                "domain": info.get("Domain", ""),
                "logon_server": info.get("Logon Server", ""),
                "total_memory": info.get("Total Physical Memory", ""),
                "system_type": info.get("System Type", ""),
            },
            "host": {"hostname": hostname},
        }

        # Hotfixes — each is an individual finding
        hotfix_lines = [v for k, v in info.items() if "Hotfix" in k or "KB" in v[:3]]
        for hf in hotfix_lines:
            if hf.startswith("KB"):
                yield {
                    "timestamp": self._snap_ts,
                    "timestamp_desc": "Hotfix Installed (Collection Time)",
                    "message": f"Hotfix: {hf}",
                    "artifact_type": "system_info",
                    "system_info": {"hotfix": hf, "hostname": hostname},
                }

    # ── netstat.txt ───────────────────────────────────────────────────────────

    def _parse_netstat(self, path: Path) -> Generator[dict, None, None]:
        for line in self._lines(path):
            m = _NETSTAT_RE.match(line)
            if not m:
                continue
            proto, local, remote, state_or_pid, pid = m.groups()
            proto = proto.upper()

            # Determine state vs PID (UDP lines have PID where state would be)
            if proto == "UDP":
                pid = state_or_pid
                state = ""
            else:
                state = state_or_pid
                # PID may be in group 5

            local_ip, _, local_port = local.rpartition(":")
            remote_ip, _, remote_port = remote.rpartition(":")

            yield {
                "timestamp": self._snap_ts,
                "timestamp_desc": "Network Connection Snapshot",
                "message": f"{proto} {local} → {remote}  {state}  pid={pid or '?'}",
                "artifact_type": "network_conn",
                "network_conn": {
                    "protocol": proto,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": state,
                    "pid": pid or "",
                },
                "network": {
                    "protocol": proto,
                    "src_ip": local_ip,
                    "dst_ip": remote_ip,
                    "src_port": local_port,
                    "dst_port": remote_port,
                },
                "process": {"pid": pid or ""},
            }

    # ── tasklist.txt ──────────────────────────────────────────────────────────

    def _parse_tasklist(self, path: Path) -> Generator[dict, None, None]:
        """Handles both default format and /SVC (services) format."""
        for line in self._lines(path):
            if not line.strip() or line.startswith("=") or line.startswith("Image"):
                continue
            m = _TASKLIST_RE.match(line)
            if not m:
                continue
            name, pid, session, session_num, mem_k = m.groups()
            name = name.strip()
            mem_bytes = int(mem_k.replace(",", "")) * 1024 if mem_k else 0
            yield {
                "timestamp": self._snap_ts,
                "timestamp_desc": "Process Snapshot",
                "message": f"Process: {name}  pid={pid}  mem={mem_k}K",
                "artifact_type": "process",
                "process": {
                    "name": name,
                    "pid": pid,
                    "session": session,
                    "memory_bytes": mem_bytes,
                },
            }

    # ── services.txt ──────────────────────────────────────────────────────────

    def _parse_services(self, path: Path) -> Generator[dict, None, None]:
        """
        Handles 'sc query' style output:
          SERVICE_NAME: <name>
          DISPLAY_NAME: <name>
          STATE: 4  RUNNING
          ...
        And 'Get-Service' CSV-like output.
        """
        current: dict[str, str] = {}
        for line in self._lines(path):
            line = line.strip()
            if not line:
                if current:
                    yield self._service_event(current)
                    current = {}
                continue
            if ":" in line and not line.startswith(" "):
                key, _, val = line.partition(":")
                current[key.strip().upper()] = val.strip()

        if current:
            yield self._service_event(current)

    def _service_event(self, svc: dict) -> dict:
        name = svc.get("SERVICE_NAME", svc.get("NAME", ""))
        display = svc.get("DISPLAY_NAME", "")
        state = svc.get("STATE", "")
        # "4  RUNNING" → extract just the text
        if state and state[0].isdigit():
            state = state.split(None, 1)[-1] if " " in state else state
        start_type = svc.get("START_TYPE", svc.get("STARTTYPE", ""))
        binary = svc.get("BINARY_PATH_NAME", svc.get("BINARYPATHNAME", ""))
        return {
            "timestamp": getattr(self, "_snap_ts", ""),
            "timestamp_desc": "Service Snapshot",
            "message": f"Service: {display or name}  state={state}  start={start_type}",
            "artifact_type": "service",
            "service": {
                "name": name,
                "display_name": display,
                "state": state,
                "start_type": start_type,
                "binary_path": binary,
            },
        }

    # ── installed_software.txt ────────────────────────────────────────────────

    def _parse_installed_software(self, path: Path) -> Generator[dict, None, None]:
        """
        Handles 'Get-WmiObject Win32_Product' or 'wmic product' output.
        Lines: "Name                 Version   Publisher   InstallDate"
        Also handles CSV-like output.
        """
        lines = self._lines(path)
        if not lines:
            return

        # Check if CSV (contains commas)
        if lines and "," in lines[0]:
            headers = [h.strip().lower() for h in lines[0].split(",")]
            for line in lines[1:]:
                if not line.strip():
                    continue
                values = [v.strip() for v in line.split(",")]
                row = dict(zip(headers, values))
                name = row.get("name", row.get("displayname", ""))
                if not name:
                    continue
                yield {
                    "timestamp": self._snap_ts,
                    "timestamp_desc": "Installed Software (Collection Time)",
                    "message": f"{name} {row.get('version', '')} ({row.get('publisher', '')})",
                    "artifact_type": "installed_software",
                    "installed_software": {
                        "name": name,
                        "version": row.get("version", ""),
                        "publisher": row.get("publisher", row.get("vendor", "")),
                        "install_date": row.get("installdate", row.get("install_date", "")),
                    },
                }
            return

        # Plain text: try to extract Name/Version/Publisher patterns
        for line in lines:
            if not line.strip() or line.startswith("Name") or line.startswith("---"):
                continue
            # Heuristic: line starts with software name, has version-like token
            parts = line.split(None, 3)
            if len(parts) >= 1:
                yield {
                    "timestamp": self._snap_ts,
                    "timestamp_desc": "Installed Software (Collection Time)",
                    "message": line.strip(),
                    "artifact_type": "installed_software",
                    "installed_software": {
                        "name": line.strip(),
                    },
                }

    # ── startup_items.txt ─────────────────────────────────────────────────────

    def _parse_startup_items(self, path: Path) -> Generator[dict, None, None]:
        for line in self._lines(path):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Expect tab or multi-space delimited: Name   Location   Command
            parts = re.split(r"\t| {3,}", line, maxsplit=2)
            if len(parts) >= 3:
                name, location, command = parts[0].strip(), parts[1].strip(), parts[2].strip()
            elif len(parts) == 2:
                name, location, command = parts[0].strip(), parts[1].strip(), ""
            else:
                name, location, command = line, "", ""

            yield {
                "timestamp": self._snap_ts,
                "timestamp_desc": "Startup Item (Collection Time)",
                "message": f"Startup: {name}  loc={location}  cmd={command}",
                "artifact_type": "startup_item",
                "startup_item": {
                    "name": name,
                    "location": location,
                    "command": command,
                },
                "process": {"command_line": command} if command else {},
            }

    # ── pfirewall.log ─────────────────────────────────────────────────────────

    def _parse_firewall_log(self, path: Path) -> Generator[dict, None, None]:
        for line in self._lines(path):
            if line.startswith("#") or not line.strip():
                continue
            m = _FW_RE.match(line)
            if not m:
                continue
            ts_str, action, proto, src_ip, dst_ip, src_port, dst_port = m.groups()
            # Normalise timestamp
            try:
                ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC).isoformat()
            except ValueError:
                ts = None
            yield {
                "timestamp": ts,
                "timestamp_desc": "Firewall Event",
                "message": f"FW {action} {proto} {src_ip}:{src_port} → {dst_ip}:{dst_port}",
                "artifact_type": "firewall_log",
                "firewall_log": {
                    "action": action,
                    "protocol": proto,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                },
                "network": {
                    "action": action,
                    "protocol": proto,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                },
            }

    # ── IIS W3C logs (u_ex*.log) ──────────────────────────────────────────────

    def _parse_iis_log(self, path: Path) -> Generator[dict, None, None]:
        """
        IIS W3C Extended Log Format — header lines define the field order.
        #Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip ...
        """
        fields: list[str] = []
        for line in self._lines(path):
            if line.startswith("#Fields:"):
                fields = line[len("#Fields:") :].strip().split()
                continue
            if line.startswith("#") or not line.strip():
                continue
            if not fields:
                continue

            parts = line.split()
            if len(parts) < len(fields):
                parts += ["-"] * (len(fields) - len(parts))
            row = dict(zip(fields, parts))

            date = row.get("date", "")
            time = row.get("time", "")
            ts = None
            if date and time:
                try:
                    ts = (
                        datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S")
                        .replace(tzinfo=UTC)
                        .isoformat()
                    )
                except ValueError:
                    pass

            method = row.get("cs-method", "-")
            uri_stem = row.get("cs-uri-stem", "-")
            uri_qry = row.get("cs-uri-query", "-")
            status = row.get("sc-status", row.get("sc-win32-status", "-"))
            client = row.get("c-ip", "-")
            server = row.get("s-ip", "-")
            port = row.get("s-port", "-")
            user = row.get("cs-username", "-")
            ua = row.get("cs(user-agent)", "-")

            uri = uri_stem if uri_qry in ("-", "") else f"{uri_stem}?{uri_qry}"
            yield {
                "timestamp": ts,
                "timestamp_desc": "IIS Request",
                "message": f"IIS {method} {uri}  status={status}  client={client}",
                "artifact_type": "iis_access_log",
                "http": {
                    "method": method,
                    "uri": uri,
                    "status_code": status,
                    "user_agent": ua,
                },
                "network": {
                    "src_ip": client,
                    "dst_ip": server,
                    "dst_port": port,
                },
                "user": {"name": user if user != "-" else ""},
            }

    def get_stats(self) -> dict[str, Any]:
        return {}
