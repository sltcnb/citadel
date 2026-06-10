"""
IPTables Plugin — parses iptables-save and iptables-L output.

Handles two formats:
  1. iptables-save / ip6tables-save
       *filter
       :INPUT ACCEPT [0:0]
       -A INPUT -p tcp --dport 22 -j ACCEPT
       COMMIT
  2. iptables -L -v -n
       Chain INPUT (policy ACCEPT)
        pkts bytes target  prot opt in  out  source       destination
           0     0 ACCEPT  tcp  --  *   *    0.0.0.0/0    0.0.0.0/0    tcp dpt:22

Each -A rule (or -L row) becomes one indexed event with:
  iptables.table, iptables.chain, iptables.target, iptables.ctstate,
  iptables.modules, iptables.comment,
  network.protocol, network.src_ip, network.dst_ip, network.src_port,
  network.dst_port, network.in_iface, network.out_iface, network.action

Priority 95 — above json_file (15) which would otherwise chunk iptables
files as raw text.  Below syslog (100) intentionally: syslog won't match
iptables-save files because they don't start with RFC3164 timestamps.
"""

from __future__ import annotations

import re
import shlex
import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

# ── Format detection ──────────────────────────────────────────────────────────

_TABLE_RE = re.compile(r"^\*(\w+)")
_CHAIN_POLICY_RE = re.compile(r"^:(\S+)\s+(\S+)\s+\[(\d+):(\d+)\]")
_SAVE_RULE_RE = re.compile(r"^-A\s+(\S+)\s+(.+)$")
_SAVE_TS_RE = re.compile(r"#.*?on\s+(.+)$", re.IGNORECASE)

# iptables -L chain header
_L_CHAIN_RE = re.compile(r"^Chain\s+(\S+)\s+\((?:policy\s+(\S+)|(\d+)\s+references)", re.IGNORECASE)
# iptables -L column header row
_L_HEADER_RE = re.compile(r"^\s*pkts\s+bytes\s+target", re.IGNORECASE)
# iptables -L data row (handles K/M/G suffixes on packet/byte counts)
_L_ROW_RE = re.compile(
    r"^\s*(\d+[KMG]?)\s+"  # pkts
    r"(\d+[KMG]?)\s+"  # bytes
    r"(\S+)\s+"  # target
    r"(\S+)\s+"  # prot
    r"\S+\s+"  # opt
    r"(\S+)\s+"  # in-iface
    r"(\S+)\s+"  # out-iface
    r"(\S+)\s+"  # source
    r"(\S+)"  # destination
    r"(?:\s+(.*))?$"  # extra options
)

_KNOWN_NAMES = frozenset(
    {
        "iptables_save.log",
        "iptables_rules.log",
        "iptables.log",
        "iptables-save.log",
        "iptables-restore.log",
        "ip6tables_save.log",
        "ip6tables_rules.log",
        "ip6tables.log",
        "nftables_save.log",
        "firewall_rules.log",
        "firewall.log",
    }
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _parse_save_args(args_str: str) -> dict[str, Any]:
    """Parse iptables-save rule argument string into structured fields."""
    result: dict[str, Any] = {}
    try:
        tokens = shlex.split(args_str)
    except ValueError:
        tokens = args_str.split()

    modules: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""

        if tok == "-j":
            result["target"] = nxt
            i += 2
        elif tok == "-p":
            result["protocol"] = nxt
            i += 2
        elif tok in ("-s", "--source"):
            result["src_ip"] = nxt
            i += 2
        elif tok in ("-d", "--destination"):
            result["dst_ip"] = nxt
            i += 2
        elif tok in ("-i", "--in-interface"):
            result["in_iface"] = nxt
            i += 2
        elif tok in ("-o", "--out-interface"):
            result["out_iface"] = nxt
            i += 2
        elif tok in ("--dport", "--destination-port"):
            result["dst_port"] = nxt
            i += 2
        elif tok in ("--sport", "--source-port"):
            result["src_port"] = nxt
            i += 2
        elif tok in ("--ctstate", "--state"):
            result["ctstate"] = nxt
            i += 2
        elif tok == "--comment":
            result["comment"] = nxt
            i += 2
        elif tok == "--to-destination":
            result["to_destination"] = nxt
            i += 2
        elif tok == "--to-source":
            result["to_source"] = nxt
            i += 2
        elif tok == "--log-prefix":
            result["log_prefix"] = nxt
            i += 2
        elif tok == "-m":
            modules.append(nxt)
            i += 2
        elif tok in ("!", "--not"):
            i += 1
        else:
            i += 1

    if modules:
        result["modules"] = modules
    return result


def _action_from_target(target: str) -> str:
    """Map iptables target to a normalised network.action string."""
    _map = {
        "ACCEPT": "allow",
        "RETURN": "return",
        "LOG": "log",
        "DROP": "deny",
        "REJECT": "deny",
        "MASQUERADE": "nat",
        "DNAT": "nat",
        "SNAT": "nat",
        "REDIRECT": "nat",
        "TPROXY": "nat",
    }
    return _map.get(target.upper(), "unknown")


def _detect_format(path: Path) -> str | None:
    """Return 'save' or 'list' based on first meaningful lines, or None."""
    try:
        with open(path, errors="replace") as fh:
            for _ in range(10):
                line = fh.readline()
                if not line:
                    break
                stripped = line.strip()
                if _TABLE_RE.match(stripped):
                    return "save"
                if _CHAIN_POLICY_RE.match(stripped):
                    return "save"
                if stripped.startswith("-A "):
                    return "save"
                if _L_CHAIN_RE.match(stripped):
                    return "list"
    except OSError:
        pass
    return None


# ── Plugin ────────────────────────────────────────────────────────────────────


class IptablesPlugin(BasePlugin):
    """Parses iptables-save and iptables -L output into structured rule events."""

    PLUGIN_NAME = "iptables"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "iptables_rule"
    SUPPORTED_EXTENSIONS = [".log", ".txt"]
    SUPPORTED_MIME_TYPES = ["text/plain"]
    PLUGIN_PRIORITY = 95

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(_KNOWN_NAMES)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        # First match: known iptables filename → always claim
        if file_path.name.lower() in _KNOWN_NAMES:
            return True
        # NEVER probe arbitrary files. _detect_format opens the file with
        # errors='replace' which means a binary file (e.g. a .pf prefetch
        # or .lnk shortcut) can produce text matching the chain regex by
        # accident, leading iptables (priority 95) to silently hijack the
        # wrong plugin. Restrict probing to plausibly-text extensions.
        if file_path.suffix.lower() not in (".log", ".txt"):
            return False
        return _detect_format(file_path) is not None

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        fmt = _detect_format(path)
        if fmt == "save":
            yield from self._parse_save(path)
        elif fmt == "list":
            yield from self._parse_list(path)

    # ── iptables-save ─────────────────────────────────────────────────────────

    def _parse_save(self, path: Path) -> Generator[dict[str, Any], None, None]:
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open iptables file: {exc}") from exc

        snap_ts = _mtime_or_now(path)
        current_table = "filter"
        chain_policies: dict[str, str] = {}

        with fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    # Grab snapshot timestamp from save header comment
                    if line.startswith("#"):
                        m = _SAVE_TS_RE.match(line)
                        if m:
                            snap_ts = _parse_save_ts(m.group(1)) or snap_ts
                    continue

                if line == "COMMIT":
                    chain_policies = {}
                    continue

                # *table
                m = _TABLE_RE.match(line)
                if m:
                    current_table = m.group(1).lower()
                    continue

                # :CHAIN POLICY [pkts:bytes]
                m = _CHAIN_POLICY_RE.match(line)
                if m:
                    chain_policies[m.group(1)] = m.group(2)
                    continue

                # -A CHAIN <args>
                m = _SAVE_RULE_RE.match(line)
                if not m:
                    continue

                chain = m.group(1)
                fields = _parse_save_args(m.group(2))
                target = fields.get("target", "")

                msg = f"{current_table.upper()}/{chain} → {target}"
                if fields.get("protocol") and fields["protocol"] != "all":
                    msg += f" ({fields['protocol']})"
                if fields.get("src_ip") and fields["src_ip"] != "0.0.0.0/0":
                    msg += f" src:{fields['src_ip']}"
                if fields.get("dst_ip") and fields["dst_ip"] != "0.0.0.0/0":
                    msg += f" dst:{fields['dst_ip']}"
                if fields.get("dst_port"):
                    msg += f":{fields['dst_port']}"
                if fields.get("ctstate"):
                    msg += f" [{fields['ctstate']}]"
                if fields.get("comment"):
                    msg += f" # {fields['comment']}"

                event: dict[str, Any] = {
                    "fo_id": str(uuid.uuid4()),
                    "timestamp": snap_ts,
                    "timestamp_desc": "Firewall Rule Snapshot",
                    "message": msg,
                    "artifact_type": "iptables_rule",
                    "iptables": {
                        "table": current_table,
                        "chain": chain,
                        "target": target,
                        **{
                            k: v
                            for k, v in fields.items()
                            if k
                            not in (
                                "target",
                                "src_ip",
                                "dst_ip",
                                "src_port",
                                "dst_port",
                                "in_iface",
                                "out_iface",
                                "protocol",
                            )
                        },
                    },
                    "raw": {"line": line},
                }

                net: dict[str, Any] = {"action": _action_from_target(target)}
                for src_k, dst_k in [
                    ("protocol", "protocol"),
                    ("src_ip", "src_ip"),
                    ("dst_ip", "dst_ip"),
                    ("src_port", "src_port"),
                    ("dst_port", "dst_port"),
                    ("in_iface", "in_iface"),
                    ("out_iface", "out_iface"),
                ]:
                    if src_k in fields:
                        net[dst_k] = fields[src_k]
                event["network"] = net

                yield event

    # ── iptables -L -v -n ─────────────────────────────────────────────────────

    def _parse_list(self, path: Path) -> Generator[dict[str, Any], None, None]:
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open iptables file: {exc}") from exc

        snap_ts = _mtime_or_now(path)
        current_table = "filter"
        current_chain = ""
        in_chain = False

        with fh:
            for raw in fh:
                line = raw.rstrip("\n")
                stripped = line.strip()
                if not stripped:
                    continue

                # Table comment (iptables-legacy-save sometimes mixes in)
                m = _TABLE_RE.match(stripped)
                if m:
                    current_table = m.group(1).lower()
                    continue

                # Chain header
                m = _L_CHAIN_RE.match(stripped)
                if m:
                    current_chain = m.group(1)
                    in_chain = True
                    continue

                # Column header row
                if _L_HEADER_RE.match(stripped):
                    continue

                if not in_chain:
                    continue

                m = _L_ROW_RE.match(line)
                if not m:
                    continue

                _pkts, _bytes, target, proto, in_if, out_if, src, dst, opts = m.groups()

                clean = lambda v: "" if v in ("*", "--", "any", "0.0.0.0/0") else v

                msg = f"{current_table.upper()}/{current_chain} → {target}"
                if proto and proto not in ("all", "--"):
                    msg += f" ({proto})"
                if clean(src):
                    msg += f" src:{src}"
                if clean(dst):
                    msg += f" dst:{dst}"
                if opts:
                    msg += f" {opts.strip()}"

                event: dict[str, Any] = {
                    "fo_id": str(uuid.uuid4()),
                    "timestamp": snap_ts,
                    "timestamp_desc": "Firewall Rule Snapshot",
                    "message": msg,
                    "artifact_type": "iptables_rule",
                    "iptables": {
                        "table": current_table,
                        "chain": current_chain,
                        "target": target,
                        "options": opts.strip() if opts else "",
                    },
                    "network": {
                        "action": _action_from_target(target),
                        "protocol": proto if proto not in ("all", "--") else "",
                        "src_ip": clean(src),
                        "dst_ip": clean(dst),
                        "in_iface": clean(in_if),
                        "out_iface": clean(out_if),
                    },
                    "raw": {"line": line},
                }
                yield event

    def get_stats(self) -> dict[str, Any]:
        return {}


# ── Timestamp helpers ─────────────────────────────────────────────────────────


def _mtime_or_now(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


_SAVE_TS_FMT = "%a %b %d %H:%M:%S %Y"


def _parse_save_ts(raw: str) -> str | None:
    """Parse the timestamp from the iptables-save header comment."""
    raw = raw.strip()
    try:
        dt = datetime.strptime(raw, _SAVE_TS_FMT).replace(tzinfo=UTC)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
