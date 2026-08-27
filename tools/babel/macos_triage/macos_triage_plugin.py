"""
macOS Triage Plugin — structured parsing of the live macOS triage snapshot.

``MacOSCollector._system_triage`` (tools/talon/collect.py) runs ~18 commands and
concatenates their output into a single ``system_triage.txt``, each preceded by
a banner::

    ============================================================
    NETWORK SOCKETS
    ============================================================
    tcp4  0  0  192.168.1.10.52344  178.16.53.137.443  ESTABLISHED ...

Before this parser existed that whole file routed to ``linux_triage``, which
matches the filename but only knows ``_parse_sysinfo`` — so a macOS bundle
yielded exactly ONE ``system_info`` event and silently discarded the process
list, the socket table, the ARP cache, the login history and the persistence
inventory. A real investigation into a macOS host then found "no process,
network, or browser artifacts" and closed inconclusive, with the evidence
sitting in the case the whole time.

Section → artifact_type mapping deliberately reuses the types the Linux and
Windows triage parsers already emit, so existing timeline filters, detection
rules and dashboards work on macOS hosts with no change:

  OS VERSION / UNAME       → system_info      (sw_vers, uname -a)
  PROCESSES                → process          (ps auxww, BSD columns)
  NETWORK SOCKETS          → network_conn     (netstat -anv, IP.PORT notation)
  NETWORK IFACEs           → system_info      (ifconfig)
  ROUTING TABLE            → route_entry      (netstat -rn)
  ARP CACHE                → arp_entry        (arp -an)
  CURRENT USERS            → logged_user      (who)
  LAST LOGINS              → login_event      (last -n 200)
  MOUNTS / DISK USAGE      → system_info      (mount, df -h)
  LOADED KEXTS             → kernel_module    (kextstat)
  LAUNCH DAEMONS           → service          (launchctl list)
  INSTALLED APPS           → installed_software (system_profiler)
  NETWORK SERVICES         → system_info      (networksetup)
  FIREWALL                 → system_info      (socketfilterfw)
  SUID FILES               → file             (find / -perm -4000 -ls)
  ENVIRONMENT              → env_variable     (env)

Every event sets ``os="macos"`` explicitly. It has to: the shared taxonomy in
citadel_contracts maps ``process``/``network_conn``/``service`` to "windows",
which is right for their most common source and wrong here, and an unqualified
``classify_os`` would file a macOS process list under Windows.

Every event also carries ``host.hostname`` parsed from the UNAME section. A
host-scoped search is the first thing an analyst runs, and a triage snapshot
that does not name its host is invisible to it.

Priority 116 — one above linux_triage (115), which claims the same filename.
``can_handle`` additionally requires Darwin-shaped content, so a Linux bundle
still routes to linux_triage.
"""

from __future__ import annotations

import re
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

# ── Section banner ────────────────────────────────────────────────────────────
# Talon writes "\n" + "="*60 + "\n" + HEADER + "\n" + "="*60. Accept any run of
# 3+ '=' so a future width change doesn't silently stop matching.
_BANNER_RE = re.compile(r"^={3,}\s*$")

# Filenames this parser answers to. Talon writes system_triage.txt on both
# macOS and Linux; content sniffing in can_handle() separates them.
_KNOWN_NAMES = frozenset({"system_triage.txt", "macos_triage.txt"})

# Markers that make a system_triage.txt unambiguously macOS. Any one is enough:
# a truncated collection may be missing most sections.
_MACOS_MARKERS = (
    "LOADED KEXTS",
    "LAUNCH DAEMONS",
    "NETWORK SERVICES",
    "productversion:",
    "productname:\tmacos",
    "darwin kernel version",
)
# Sniff depth. The OS VERSION / UNAME banners are the first two sections, so a
# few KB is plenty, and a 200 MB ps listing must not be read to route a file.
_SNIFF_BYTES = 65536

# ── ps auxww (BSD) ────────────────────────────────────────────────────────────
# "tmoll  501  0.5  0.3 12345678  45678   ??  S     9:00AM   0:01.23 /path/cmd"
# TT is "??" for a process with no controlling terminal; STARTED is one of
# "9:00AM", "Tue09AM", "25Aug24"; COMMAND may contain spaces (auxww = no clip).
_PS_RE = re.compile(
    r"^(?P<user>[\w.\-+$#/\\]+)\s+"
    r"(?P<pid>\d+)\s+"
    r"(?P<cpu>[\d.]+)\s+"
    r"(?P<mem>[\d.]+)\s+"
    r"(?P<vsz>\d+)\s+"
    r"(?P<rss>\d+)\s+"
    r"(?P<tt>\S+)\s+"
    r"(?P<stat>[A-Za-z][\w+<>ELNsWX?]*)\s+"
    r"(?P<started>\S+)\s+"
    r"(?P<time>[\d:.]+)\s+"
    r"(?P<command>.+)$"
)
_PS_HEADER_RE = re.compile(r"^\s*USER\s+PID\s+%CPU", re.IGNORECASE)

# ── netstat -anv ──────────────────────────────────────────────────────────────
# macOS writes address.port, NOT address:port — "192.168.1.10.52344". For IPv6
# it writes "fe80::1%en0.52344". The trailing columns from -v vary by release,
# so only the leading fixed columns are matched and pid is picked out
# positionally from what follows.
_NETSTAT_RE = re.compile(
    r"^(?P<proto>tcp4|tcp6|tcp46|udp4|udp6|udp46)\s+"
    r"(?P<recvq>\d+)\s+"
    r"(?P<sendq>\d+)\s+"
    r"(?P<local>\S+)\s+"
    r"(?P<foreign>\S+)"
    r"(?:\s+(?P<state>[A-Z_]+))?"
    r"(?P<rest>.*)$"
)
# -v appends "rhiwat shiwat pid epid ..." — pid is the 3rd numeric column of
# the remainder. Matched loosely so a column added upstream doesn't break it.
_NETSTAT_PID_RE = re.compile(r"^\s+\d+\s+\d+\s+(?P<pid>\d+)\s")

# ── arp -an ───────────────────────────────────────────────────────────────────
# "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
# An incomplete entry writes "(incomplete)" where the MAC would be.
_ARP_RE = re.compile(
    r"^(?P<name>\S+)\s+\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]+|\(incomplete\))"
    r"(?:\s+on\s+(?P<iface>\S+))?"
    r"(?P<flags>.*)$"
)

# ── netstat -rn ───────────────────────────────────────────────────────────────
# "default            192.168.1.1        UGScg                 en0"
_ROUTE_RE = re.compile(
    r"^(?P<dest>[\w.:/%\-]+|default)\s+"
    r"(?P<gateway>[\w.:%\-]+|link#\d+)\s+"
    r"(?P<flags>[A-Za-z]+)\s+"
    r"(?P<netif>\S+)"
    r"(?:\s+(?P<expire>\S+))?\s*$"
)

# ── who ───────────────────────────────────────────────────────────────────────
# "tmoll    console  Aug 25 09:00"  /  "tmoll  ttys000  Aug 25 09:05 (10.0.0.5)"
_WHO_RE = re.compile(
    r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+"
    r"(?P<when>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2})"
    r"(?:\s+\((?P<from>[^)]*)\))?\s*$"
)

# ── last -n 200 ───────────────────────────────────────────────────────────────
# "tmoll  console   Mon Aug 25 09:00   still logged in"
# "tmoll  ttys000   10.0.0.5   Mon Aug 25 09:05 - 09:30  (00:25)"
# "reboot  ~         Mon Aug 25 08:55"
_LAST_RE = re.compile(
    r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+"
    r"(?:(?P<from>[\w.:\-]+)\s+)?"
    r"(?P<when>[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2})"
    r"(?P<tail>.*)$"
)

# ── kextstat ──────────────────────────────────────────────────────────────────
# "  145    0 0xffffff7f8xxxxx 0x8000  0x8000  com.evil.kext (1.0) UUID <5 6>"
_KEXT_RE = re.compile(
    r"^\s*(?P<index>\d+)\s+(?P<refs>\d+)\s+(?P<address>0x[0-9a-fA-F]+)\s+"
    r"(?P<size>0x[0-9a-fA-F]+)\s+(?P<wired>0x[0-9a-fA-F]+)\s+"
    r"(?P<name>[\w.\-]+)\s*(?:\((?P<version>[^)]*)\))?"
)

# ── launchctl list ────────────────────────────────────────────────────────────
# "501\t0\tcom.apple.Finder"  — PID is "-" for a job that is not running.
_LAUNCHCTL_RE = re.compile(r"^(?P<pid>-|\d+)\s+(?P<status>-|-?\d+)\s+(?P<label>\S+)\s*$")

# ── find / -perm -4000 -type f -ls ────────────────────────────────────────────
# "12345    64 -rwsr-xr-x  1 root  wheel  64512 Jan  1 00:00 /usr/bin/sudo"
_SUID_RE = re.compile(
    r"^\s*\d+\s+\d+\s+(?P<mode>[-bcdlps][rwxsStT-]{9})[+@.]?\s+\d+\s+"
    r"(?P<owner>\S+)\s+(?P<group>\S+)\s+(?P<size>\d+)\s+"
    r"(?P<date>\w{3}\s+\d{1,2}\s+[\d:]+)\s+(?P<path>.+)$"
)

# ── system_profiler SPApplicationsDataType ────────────────────────────────────
# "    Google Chrome:" then indented "      Version: 120.0.6099.109" etc.
_APP_NAME_RE = re.compile(r"^ {4}(?P<name>\S.*?):\s*$")
_APP_ATTR_RE = re.compile(r"^ {6,}(?P<key>[\w ]+):\s*(?P<value>.*)$")

# Sections rolled up whole into a single system_info event rather than parsed
# line-by-line: they are context, not per-row evidence.
_CONTEXT_SECTIONS = {
    "NETWORK IFACEs",
    "MOUNTS",
    "DISK USAGE",
    "NETWORK SERVICES",
    "FIREWALL",
}

# Prefixes an OS-shipped setuid binary lives under. /usr/bin/sudo is expected;
# a setuid file anywhere else is the finding.
_SYSTEM_SUID_PREFIXES = (
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/libexec/",
    "/bin/",
    "/sbin/",
    "/System/",
)

_MAX_SECTION_EVENTS = 20000  # per-section guard against a pathological listing


def _file_mtime(path: Path) -> str:
    """Snapshot time for sections whose rows carry no timestamp of their own."""
    try:
        return (
            datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat().replace("+00:00", "Z")
        )
    except OSError:
        return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _split_addr_port(raw: str) -> tuple[str, int | None]:
    """Split macOS netstat's ``address.port`` notation.

    Not ``address:port``: on macOS the separator is a dot, which collides with
    IPv4 ("192.168.1.10.52344" — the port is the 5th dotted field, not part of
    the address) and appears after the zone id for IPv6 ("fe80::1%en0.52344").
    An asterisk means "any" in either half ("*.443", "*.*").
    """
    raw = raw.strip()
    if not raw or "." not in raw:
        return raw, None
    addr, _, port_s = raw.rpartition(".")
    if port_s == "*":
        return (addr or "*"), None
    if not port_s.isdigit():
        return raw, None
    return (addr or "*"), int(port_s)


def _split_argv0(command: str) -> str:
    """Best-effort executable path out of a ``ps auxww`` COMMAND column.

    Splitting on the first space is wrong on macOS, where the common case is a
    bundle path that contains one:
    ``/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --flag``.
    Three rules, most specific first:

      1. A bundle path ends at the segment after ``.app/Contents/MacOS/``.
      2. An absolute path runs until the first token that starts with ``-``
         (the first flag), since a bundle path may hold several spaces.
      3. Anything else (a bare command name) is the first token.

    Rule 2 over-captures for ``/usr/bin/foo positional-arg``, which is rare on
    macOS and costs only a slightly long path string; the full command line is
    preserved verbatim on the event either way.
    """
    command = command.strip()
    if not command:
        return ""
    marker = ".app/Contents/MacOS/"
    idx = command.find(marker)
    if idx != -1:
        after = command[idx + len(marker) :]
        # The binary name is the rest of that path segment: up to the next "/"
        # (a nested helper) or the next flag token.
        cut = len(after)
        slash = after.find("/")
        if slash != -1:
            cut = slash
        flag = after.find(" -")
        if flag != -1:
            cut = min(cut, flag)
        return command[: idx + len(marker) + cut].rstrip()
    if command.startswith("/"):
        tokens = command.split(" ")
        kept: list[str] = []
        for tok in tokens:
            if tok.startswith("-") and kept:
                break
            kept.append(tok)
        return " ".join(kept)
    return command.split()[0]


def _parse_last_when(when: str, tail: str) -> str:
    """``last`` prints "Mon Aug 25 09:00" with no year — infer the most recent
    one that is not in the future, the same convention syslog parsing uses."""
    now = datetime.now(UTC)
    for year in (now.year, now.year - 1):
        try:
            dt = datetime.strptime(f"{when} {year}", "%a %b %d %H:%M %Y").replace(tzinfo=UTC)
        except ValueError:
            continue
        if dt <= now:
            return dt.isoformat().replace("+00:00", "Z")
    return ""


class MacOSTriagePlugin(BasePlugin):
    """Parses the macOS live-triage snapshot into per-section timeline events."""

    PLUGIN_NAME = "macos_triage"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "macos_triage"
    SUPPORTED_EXTENSIONS = [".txt", ".log"]
    SUPPORTED_MIME_TYPES = ["text/plain", "text/x-macos-triage"]
    # One above linux_triage (115): both claim system_triage.txt, and the
    # content check below is what actually decides which bundle is whose.
    PLUGIN_PRIORITY = 116

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(_KNOWN_NAMES)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        if file_path.name.lower() not in _KNOWN_NAMES:
            return False
        # Name alone is not enough — Linux bundles use the same filename and
        # must keep routing to linux_triage.
        try:
            with open(file_path, errors="replace") as fh:
                head = fh.read(_SNIFF_BYTES)
        except OSError:
            return False
        lowered = head.lower()
        return any(m.lower() in lowered for m in _MACOS_MARKERS)

    def __init__(self, context) -> None:
        super().__init__(context)
        self._hostname = ""
        self._records_read = 0
        self._records_skipped = 0

    # ── Entry point ───────────────────────────────────────────────────────────

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            with open(path, errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError as exc:
            raise PluginFatalError(f"Cannot open {path.name}: {exc}") from exc

        snap_ts = _file_mtime(path)
        sections = self._split_sections(lines)

        # UNAME first, out of order: every other event wants the hostname, and
        # a host-scoped search is the first thing an analyst runs.
        self._hostname = self._extract_hostname(sections)

        handlers = {
            "OS VERSION": self._parse_os_version,
            "UNAME": self._parse_uname,
            "PROCESSES": self._parse_processes,
            "NETWORK SOCKETS": self._parse_sockets,
            "ROUTING TABLE": self._parse_routes,
            "ARP CACHE": self._parse_arp,
            "CURRENT USERS": self._parse_who,
            "LAST LOGINS": self._parse_last,
            "LOADED KEXTS": self._parse_kexts,
            "LAUNCH DAEMONS": self._parse_launchctl,
            "INSTALLED APPS": self._parse_apps,
            "SUID FILES": self._parse_suid,
            "ENVIRONMENT": self._parse_env,
        }

        for header, body in sections:
            if header in _CONTEXT_SECTIONS:
                yield from self._parse_context(header, body, snap_ts)
                continue
            handler = handlers.get(header)
            if handler is None:
                # An unrecognised section is still evidence — keep it as
                # context rather than dropping it on the floor.
                yield from self._parse_context(header, body, snap_ts)
                continue
            emitted = 0
            for evt in handler(body, snap_ts):
                yield evt
                emitted += 1
                if emitted >= _MAX_SECTION_EVENTS:
                    self.log.warning(
                        "macos_triage: %s section capped at %d events",
                        header,
                        _MAX_SECTION_EVENTS,
                    )
                    break

    # ── Section splitting ─────────────────────────────────────────────────────

    def _split_sections(self, lines: list[str]) -> list[tuple[str, list[str]]]:
        """Split on the ``====`` / HEADER / ``====`` banner Talon writes.

        Returns ``[(header, body_lines), ...]`` in file order. Content before
        the first banner (there shouldn't be any) is discarded rather than
        guessed at.
        """
        sections: list[tuple[str, list[str]]] = []
        header: str | None = None
        body: list[str] = []
        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]
            # A banner is: ==== / TEXT / ====  on three consecutive lines.
            if (
                _BANNER_RE.match(line.strip())
                and i + 2 < n
                and _BANNER_RE.match(lines[i + 2].strip())
                and lines[i + 1].strip()
            ):
                if header is not None:
                    sections.append((header, body))
                header = lines[i + 1].strip()
                body = []
                i += 3
                continue
            if header is not None:
                body.append(line)
            i += 1
        if header is not None:
            sections.append((header, body))
        return sections

    def _extract_hostname(self, sections: list[tuple[str, list[str]]]) -> str:
        for header, body in sections:
            if header != "UNAME":
                continue
            for line in body:
                # "Darwin L20336 23.4.0 Darwin Kernel Version 23.4.0: ... arm64"
                m = re.match(r"^Darwin\s+(\S+)\s+", line.strip())
                if m:
                    return m.group(1)
        return ""

    # ── Event helper ──────────────────────────────────────────────────────────

    def _event(
        self,
        *,
        timestamp: str,
        timestamp_desc: str,
        artifact_type: str,
        message: str,
        raw: dict[str, Any],
        **extra: Any,
    ) -> dict[str, Any]:
        """Build one event with the macOS/host context every section shares.

        ``os`` is set explicitly rather than left to ``classify_os``: the shared
        taxonomy files ``process``/``network_conn``/``service`` under "windows",
        which would put a macOS process list on the wrong side of every OS
        filter in the product.
        """
        evt: dict[str, Any] = {
            "timestamp": timestamp,
            "timestamp_desc": timestamp_desc,
            "artifact_type": artifact_type,
            "message": message,
            "os": "macos",
            "raw": raw,
        }
        if self._hostname:
            evt["host"] = {"hostname": self._hostname}
        evt.update(extra)
        self._records_read += 1
        return evt

    # ── sw_vers ───────────────────────────────────────────────────────────────

    def _parse_os_version(self, body: list[str], ts: str) -> Generator[dict, None, None]:
        fields: dict[str, str] = {}
        for line in body:
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            if key:
                fields[key] = value.strip()
        if not fields:
            return
        product = fields.get("ProductName", "macOS")
        version = fields.get("ProductVersion", "")
        build = fields.get("BuildVersion", "")
        yield self._event(
            timestamp=ts,
            timestamp_desc="Collection Time",
            artifact_type="system_info",
            message=f"{product} {version} (build {build})".strip(),
            raw=dict(fields),
            system_info={
                "os_name": product,
                "os_version": version,
                "os_build": build,
                "hostname": self._hostname,
            },
        )

    # ── uname -a ──────────────────────────────────────────────────────────────

    def _parse_uname(self, body: list[str], ts: str) -> Generator[dict, None, None]:
        text = "\n".join(line for line in body if line.strip())
        if not text:
            return
        m = re.match(r"^Darwin\s+(?P<host>\S+)\s+(?P<kernel>\S+)\s+(?P<rest>.*)$", text.strip())
        kernel = m.group("kernel") if m else ""
        arch = text.rsplit(None, 1)[-1] if text.split() else ""
        yield self._event(
            timestamp=ts,
            timestamp_desc="Collection Time",
            artifact_type="system_info",
            message=f"Darwin kernel {kernel} on {self._hostname or 'unknown host'} ({arch})",
            raw={"uname": text[:2000]},
            system_info={
                "kernel": kernel,
                "hostname": self._hostname,
                "architecture": arch,
                "raw": text[:2000],
            },
        )

    # ── ps auxww ──────────────────────────────────────────────────────────────

    def _parse_processes(self, body: list[str], ts: str) -> Generator[dict, None, None]:
        for line in body:
            line = line.rstrip()
            if not line.strip() or _PS_HEADER_RE.match(line):
                continue
            m = _PS_RE.match(line)
            if not m:
                self._records_skipped += 1
                continue
            g = m.groupdict()
            command = g["command"].strip()
            # argv[0] is the executable; on macOS it is usually an absolute
            # path into a .app bundle, whose name contains spaces.
            exe = _split_argv0(command)
            yield self._event(
                timestamp=ts,
                timestamp_desc="Process Snapshot",
                artifact_type="process",
                message=f"{exe}  (pid={g['pid']} user={g['user']} cpu={g['cpu']}%)",
                raw=dict(g),
                process={
                    "name": exe.rsplit("/", 1)[-1] if exe else command,
                    "path": exe if exe.startswith("/") else "",
                    "command_line": command,
                    "pid": int(g["pid"]),
                },
                user={"name": g["user"]},
                macos_process={
                    "cpu_pct": float(g["cpu"]),
                    "mem_pct": float(g["mem"]),
                    "vsz_kb": int(g["vsz"]),
                    "rss_kb": int(g["rss"]),
                    "tty": g["tt"],
                    "stat": g["stat"],
                    "started": g["started"],
                    "cpu_time": g["time"],
                },
            )

    # ── netstat -anv ──────────────────────────────────────────────────────────

    def _parse_sockets(self, body: list[str], ts: str) -> Generator[dict, None, None]:
        for line in body:
            line = line.rstrip()
            stripped = line.strip()
            if not stripped:
                continue
            # "Active LOCAL (UNIX) domain sockets" and everything after it is
            # not network traffic; stop rather than misparse it as such.
            if stripped.lower().startswith("active local"):
                break
            m = _NETSTAT_RE.match(stripped)
            if not m:
                continue
            g = m.groupdict()
            local_ip, local_port = _split_addr_port(g["local"])
            remote_ip, remote_port = _split_addr_port(g["foreign"])
            state = g["state"] or ""
            pid = None
            pm = _NETSTAT_PID_RE.match(g["rest"] or "")
            if pm:
                pid = int(pm.group("pid"))
            proto = g["proto"]
            direction = "listening" if state == "LISTEN" or remote_ip in ("*", "") else "connected"
            remote_disp = (
                f"{remote_ip}:{remote_port}" if remote_port is not None else (remote_ip or "*")
            )
            local_disp = f"{local_ip}:{local_port}" if local_port is not None else (local_ip or "*")
            msg = (
                f"{proto} {local_disp} → {remote_disp}"
                f"{f'  {state}' if state else ''}"
                f"{f'  pid={pid}' if pid else ''}"
            )
            network: dict[str, Any] = {
                "protocol": "tcp" if proto.startswith("tcp") else "udp",
                "direction": direction,
            }
            # Only set the address fields that are real. A wildcard bind is not
            # an IP, and indexing "*" as one poisons IP-based CTI matching.
            if local_ip and local_ip != "*":
                network["local_ip"] = local_ip
            if local_port is not None:
                network["local_port"] = local_port
            if remote_ip and remote_ip != "*":
                network["remote_ip"] = remote_ip
            if remote_port is not None:
                network["remote_port"] = remote_port
            extra: dict[str, Any] = {
                "network": network,
                "macos_socket": {
                    "proto": proto,
                    "state": state,
                    "recv_q": int(g["recvq"]),
                    "send_q": int(g["sendq"]),
                    "pid": pid,
                },
            }
            if pid:
                extra["process"] = {"pid": pid}
            yield self._event(
                timestamp=ts,
                timestamp_desc="Socket Snapshot",
                artifact_type="network_conn",
                message=msg,
                raw={"line": stripped[:1000]},
                **extra,
            )

    # ── netstat -rn ───────────────────────────────────────────────────────────

    def _parse_routes(self, body: list[str], ts: str) -> Generator[dict, None, None]:
        for line in body:
            stripped = line.strip()
            if not stripped:
                continue
            low = stripped.lower()
            if low.startswith(("routing tables", "internet:", "internet6:", "destination")):
                continue
            m = _ROUTE_RE.match(stripped)
            if not m:
                continue
            g = m.groupdict()
            yield self._event(
                timestamp=ts,
                timestamp_desc="Route Snapshot",
                artifact_type="route_entry",
                message=f"{g['dest']} via {g['gateway']} dev {g['netif']} ({g['flags']})",
                raw=dict(g),
                route_entry={
                    "destination": g["dest"],
                    "gateway": g["gateway"],
                    "flags": g["flags"],
                    "interface": g["netif"],
                    "expire": g.get("expire") or "",
                },
            )

    # ── arp -an ───────────────────────────────────────────────────────────────

    def _parse_arp(self, body: list[str], ts: str) -> Generator[dict, None, None]:
        for line in body:
            stripped = line.strip()
            if not stripped:
                continue
            m = _ARP_RE.match(stripped)
            if not m:
                continue
            g = m.groupdict()
            mac = g["mac"]
            if mac == "(incomplete)":
                mac = ""
            iface = g.get("iface") or ""
            yield self._event(
                timestamp=ts,
                timestamp_desc="ARP Snapshot",
                artifact_type="arp_entry",
                message=f"{g['ip']} is-at {mac or '(incomplete)'} on {iface or '?'}",
                raw=dict(g),
                network={"remote_ip": g["ip"]},
                arp_entry={
                    "ip": g["ip"],
                    "mac": mac,
                    "interface": iface,
                    "hostname": "" if g["name"] == "?" else g["name"],
                    "flags": (g.get("flags") or "").strip(),
                },
            )

    # ── who ───────────────────────────────────────────────────────────────────

    def _parse_who(self, body: list[str], ts: str) -> Generator[dict, None, None]:
        for line in body:
            stripped = line.strip()
            if not stripped:
                continue
            m = _WHO_RE.match(stripped)
            if not m:
                continue
            g = m.groupdict()
            src = g.get("from") or ""
            yield self._event(
                timestamp=ts,
                timestamp_desc="Session Snapshot",
                artifact_type="logged_user",
                message=f"{g['user']} on {g['tty']} since {g['when']}"
                + (f" from {src}" if src else ""),
                raw=dict(g),
                user={"name": g["user"]},
                network={"remote_ip": src} if src else {},
                logged_user={
                    "user": g["user"],
                    "tty": g["tty"],
                    "since": g["when"],
                    "from": src,
                },
            )

    # ── last -n 200 ───────────────────────────────────────────────────────────

    def _parse_last(self, body: list[str], ts: str) -> Generator[dict, None, None]:
        for line in body:
            stripped = line.strip()
            if not stripped or stripped.startswith("wtmp begins"):
                continue
            m = _LAST_RE.match(stripped)
            if not m:
                continue
            g = m.groupdict()
            when = _parse_last_when(g["when"], g["tail"])
            src = g.get("from") or ""
            tail = (g.get("tail") or "").strip()
            still = "still logged in" in tail
            yield self._event(
                # A login has a real time of its own — unlike every other
                # section here, do NOT fall back to the snapshot time, or the
                # whole login history collapses onto the collection moment.
                timestamp=when or ts,
                timestamp_desc="Login Time" if when else "Login Snapshot",
                artifact_type="login_event",
                message=f"{g['user']} logged in on {g['tty']}"
                + (f" from {src}" if src else "")
                + ("  (still logged in)" if still else ""),
                raw=dict(g),
                user={"name": g["user"]},
                network={"remote_ip": src} if src else {},
                login_event={
                    "user": g["user"],
                    "tty": g["tty"],
                    "from": src,
                    "when": g["when"],
                    "still_logged_in": still,
                    "detail": tail[:200],
                },
            )

    # ── kextstat ──────────────────────────────────────────────────────────────

    def _parse_kexts(self, body: list[str], ts: str) -> Generator[dict, None, None]:
        for line in body:
            if not line.strip() or line.lstrip().startswith("Index"):
                continue
            m = _KEXT_RE.match(line)
            if not m:
                continue
            g = m.groupdict()
            name = g["name"]
            version = g.get("version") or ""
            # Third-party kexts are the interesting ones: an Apple-signed kext
            # is background noise, a com.* stranger is a rootkit candidate.
            third_party = not name.startswith(("com.apple.", "__kernel__"))
            yield self._event(
                timestamp=ts,
                timestamp_desc="Kext Snapshot",
                artifact_type="kernel_module",
                message=f"{name}{f' ({version})' if version else ''}"
                + ("  [third-party]" if third_party else ""),
                raw=dict(g),
                kernel_module={
                    "name": name,
                    "version": version,
                    "index": int(g["index"]),
                    "refs": int(g["refs"]),
                    "address": g["address"],
                    "size": g["size"],
                    "third_party": third_party,
                },
            )

    # ── launchctl list ────────────────────────────────────────────────────────

    def _parse_launchctl(self, body: list[str], ts: str) -> Generator[dict, None, None]:
        for line in body:
            stripped = line.strip()
            if not stripped or stripped.lower().startswith("pid\tstatus") or stripped.startswith(
                "PID"
            ):
                continue
            m = _LAUNCHCTL_RE.match(stripped)
            if not m:
                continue
            g = m.groupdict()
            pid = None if g["pid"] == "-" else int(g["pid"])
            label = g["label"]
            third_party = not label.startswith(("com.apple.", "com.openssh."))
            try:
                status = int(g["status"])
            except ValueError:
                status = None
            yield self._event(
                timestamp=ts,
                timestamp_desc="Launchd Job Snapshot",
                artifact_type="service",
                message=f"{label}  (pid={pid if pid is not None else '-'} status={g['status']})"
                + ("  [third-party]" if third_party else ""),
                raw=dict(g),
                process={"pid": pid} if pid is not None else {},
                service={
                    "name": label,
                    "pid": pid,
                    "status": status,
                    "state": "running" if pid is not None else "loaded",
                    "third_party": third_party,
                },
            )

    # ── system_profiler SPApplicationsDataType ────────────────────────────────

    def _parse_apps(self, body: list[str], ts: str) -> Generator[dict, None, None]:
        """system_profiler emits a name line then indented key/value attributes.

        Yields one event per application, flushing the previous one when the
        next name line (or end of section) is reached.
        """
        name: str | None = None
        attrs: dict[str, str] = {}

        def flush() -> dict[str, Any] | None:
            if not name:
                return None
            version = attrs.get("Version", "")
            location = attrs.get("Location", "")
            signed_by = attrs.get("Signed by", "")
            obtained = attrs.get("Obtained from", "")
            # "Unknown"/"Not signed" provenance on a macOS app is the signal an
            # analyst is actually looking for in this section.
            unsigned = obtained.lower() in ("unknown", "") or not signed_by
            return self._event(
                timestamp=ts,
                timestamp_desc="Installed Application",
                artifact_type="installed_software",
                message=f"{name} {version}".strip()
                + (f"  ({obtained})" if obtained else "")
                + ("  [unsigned/unknown origin]" if unsigned else ""),
                raw=dict(attrs, name=name),
                installed_software={
                    "name": name,
                    "version": version,
                    "path": location,
                    "signed_by": signed_by,
                    "obtained_from": obtained,
                    "last_modified": attrs.get("Last Modified", ""),
                    "unsigned": unsigned,
                },
            )

        for line in body:
            if not line.strip():
                continue
            nm = _APP_NAME_RE.match(line)
            if nm:
                evt = flush()
                if evt:
                    yield evt
                name = nm.group("name").strip()
                attrs = {}
                continue
            am = _APP_ATTR_RE.match(line)
            if am and name:
                attrs[am.group("key").strip()] = am.group("value").strip()
        evt = flush()
        if evt:
            yield evt

    # ── find / -perm -4000 -type f -ls ────────────────────────────────────────

    def _parse_suid(self, body: list[str], ts: str) -> Generator[dict, None, None]:
        for line in body:
            if not line.strip():
                continue
            m = _SUID_RE.match(line)
            if not m:
                continue
            g = m.groupdict()
            path = g["path"].strip()
            # A setuid binary outside the OS-owned prefixes is the finding;
            # /usr/bin/sudo is not.
            suspicious = not path.startswith(_SYSTEM_SUID_PREFIXES)
            yield self._event(
                timestamp=ts,
                timestamp_desc="SUID File Snapshot",
                artifact_type="file",
                message=f"setuid {g['mode']} {g['owner']}:{g['group']} {path}"
                + ("  [outside system paths]" if suspicious else ""),
                raw=dict(g),
                file={
                    "path": path,
                    "name": path.rsplit("/", 1)[-1],
                    "mode": g["mode"],
                    "owner": g["owner"],
                    "group": g["group"],
                    "size": int(g["size"]),
                    "suspicious_location": suspicious,
                },
            )

    # ── env ───────────────────────────────────────────────────────────────────

    def _parse_env(self, body: list[str], ts: str) -> Generator[dict, None, None]:
        for line in body:
            stripped = line.rstrip()
            if not stripped or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            key = key.strip()
            if not key or " " in key:
                continue
            yield self._event(
                timestamp=ts,
                timestamp_desc="Environment Snapshot",
                artifact_type="env_variable",
                message=f"{key}={value[:200]}",
                raw={"key": key, "value": value[:2000]},
                env_variable={"name": key, "value": value[:2000]},
            )

    # ── Context sections (kept whole) ─────────────────────────────────────────

    def _parse_context(self, header: str, body: list[str], ts: str) -> Generator[dict, None, None]:
        text = "\n".join(line.rstrip() for line in body if line.strip())
        if not text:
            return
        yield self._event(
            timestamp=ts,
            timestamp_desc="Collection Time",
            artifact_type="system_info",
            message=f"{header}: {text[:400]}",
            raw={"section": header, "text": text[:8000]},
            system_info={
                "section": header,
                "hostname": self._hostname,
                "raw": text[:8000],
            },
        )

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_read": self._records_read,
            "records_skipped": self._records_skipped,
            "hostname": self._hostname,
        }
