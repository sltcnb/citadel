"""
Linux Auditd Plugin — parses Linux audit daemon log files.

Parses the raw auditd log format produced by /var/log/audit/audit.log:
  type=SYSCALL msg=audit(1714295856.123:456): arch=c000003e syscall=59 ...
  type=EXECVE msg=audit(1714295856.123:456): argc=3 a0="bash" a1="-c" a2="id"
  type=PATH msg=audit(1714295856.123:456): item=0 name="/bin/bash" ...
  type=USER_LOGIN msg=audit(1714295856.123:456): pid=1234 uid=0 ...

Each audit record (identified by its serial number) is emitted as a
structured event.  Related records sharing the same serial (e.g., SYSCALL +
EXECVE + PATH for a single execve call) are each emitted individually so they
appear in the Timeline at the same timestamp.

Key structured fields:
  audit.type, audit.serial, audit.syscall, audit.exe, audit.comm,
  audit.result (success/fail), audit.uid, audit.euid, audit.gid,
  process.name, process.pid, user.name

Priority 109 — above syslog (100) since audit.log is text/plain and syslog
would otherwise consume it.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

# ── Patterns ──────────────────────────────────────────────────────────────────

# type=SYSCALL msg=audit(1714295856.123:456): key=value key=value ...
_AUDIT_LINE_RE = re.compile(r"^type=(\S+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)")

# key=value parser (handles key="value with spaces" and key=value)
_KV_RE = re.compile(r'(\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(\S+))')

# Syscall number → name (most common ones; auditd should ideally decode these,
# but sometimes raw numbers appear)
_SYSCALL_NAMES: dict[int, str] = {
    59: "execve",
    322: "execveat",
    2: "open",
    257: "openat",
    3: "close",
    56: "clone",
    57: "fork",
    58: "vfork",
    105: "setuid",
    106: "setgid",
    37: "kill",
    62: "kill",
    90: "chmod",
    91: "fchmod",
    92: "chown",
    94: "lchown",
    260: "fchownat",
    263: "unlinkat",
    87: "unlink",
    80: "chdir",
    161: "chroot",
    48: "signal",
    49: "bind",
    50: "listen",
    43: "accept",
    42: "connect",
    44: "sendto",
    45: "recvfrom",
    41: "socket",
    0: "read",
    1: "write",
    85: "creat",
}

# Audit record types that represent security-relevant events
_HIGH_VALUE_TYPES = frozenset(
    {
        "SYSCALL",
        "EXECVE",
        "PATH",
        "SOCKETCALL",
        "SOCKADDR",
        "USER_AUTH",
        "USER_LOGIN",
        "USER_LOGOUT",
        "USER_CMD",
        "USER_CHAUTHTOK",
        "ADD_USER",
        "DEL_USER",
        "ADD_GROUP",
        "DEL_GROUP",
        "CRED_ACQ",
        "CRED_DISP",
        "CRED_REFR",
        "PROCTITLE",
        "CWD",
        "NETFILTER_PKT",
        "AVC",  # SELinux/AppArmor denial
        "SECCOMP",
        "KERN_MODULE",
        "CONFIG_CHANGE",
        "CRYPTO_SESSION",
        "CRYPTO_KEY_USER",
        "LOGIN",
        "LOGOUT",
    }
)

_KNOWN_NAMES = frozenset(
    {
        "audit.log",
        "auditd.log",
        "audit.log.1",
        "audit.log.2",
        "audit.log.3",
        "linux_audit.log",
        "audit_log.log",
        "ausearch.log",
    }
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _parse_kv(s: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for m in _KV_RE.finditer(s):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        result[key] = val
    return result


def _ts_from_audit(epoch_str: str) -> str:
    """Convert audit epoch (e.g. 1714295856.123) to ISO8601."""
    try:
        ts = float(epoch_str)
        dt = datetime.fromtimestamp(ts, tz=UTC)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(dt.microsecond / 1000):03d}Z"
    except (ValueError, OSError):
        return epoch_str


def _syscall_name(raw: str) -> str:
    """Return syscall name from number or pass through if already a name."""
    try:
        n = int(raw)
        return _SYSCALL_NAMES.get(n, f"syscall_{n}")
    except ValueError:
        return raw


def _detect_format(path: Path) -> bool:
    """Return True if file looks like auditd log output."""
    try:
        with open(path, errors="replace") as fh:
            for _ in range(5):
                line = fh.readline()
                if not line:
                    break
                if _AUDIT_LINE_RE.match(line.strip()):
                    return True
    except OSError:
        pass
    return False


# ── Plugin ────────────────────────────────────────────────────────────────────


class AuditdPlugin(BasePlugin):
    """Parses Linux auditd log files into structured security events."""

    PLUGIN_NAME = "auditd"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "audit_event"
    SUPPORTED_EXTENSIONS = [".log"]
    SUPPORTED_MIME_TYPES = ["text/plain", "text/x-auditd"]
    PLUGIN_PRIORITY = 109

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(_KNOWN_NAMES)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        if file_path.name.lower() in _KNOWN_NAMES:
            return True
        return _detect_format(file_path)

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open audit log: {exc}") from exc

        with fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue

                m = _AUDIT_LINE_RE.match(line)
                if not m:
                    continue

                rec_type, epoch, serial, kv_str = m.groups()
                fields = _parse_kv(kv_str)
                ts = _ts_from_audit(epoch)

                # ── Build structured event ─────────────────────────────────

                audit: dict[str, Any] = {
                    "type": rec_type,
                    "serial": serial,
                }

                msg_parts = [rec_type]
                process_obj: dict[str, Any] = {}
                user_obj: dict[str, Any] = {}
                network_obj: dict[str, Any] = {}

                if rec_type == "SYSCALL":
                    syscall = _syscall_name(fields.get("syscall", ""))
                    audit["syscall"] = syscall
                    audit["result"] = fields.get("success", fields.get("result", ""))
                    exe = fields.get("exe", "").strip('"')
                    comm = fields.get("comm", "").strip('"')
                    pid = fields.get("pid", "")
                    ppid = fields.get("ppid", "")
                    uid = fields.get("uid", "")
                    euid = fields.get("euid", "")
                    auid = fields.get("auid", "")

                    if exe:
                        audit["exe"] = exe
                    if comm:
                        audit["comm"] = comm

                    msg_parts = [f"SYSCALL {syscall}"]
                    if exe:
                        msg_parts.append(f"exe={exe}")
                    if comm and comm != exe:
                        msg_parts.append(f"comm={comm}")
                    if audit["result"] == "no":
                        msg_parts.append("[FAILED]")

                    if pid:
                        process_obj["pid"] = int(pid)
                    if ppid:
                        process_obj["ppid"] = int(ppid)
                    if comm:
                        process_obj["name"] = comm
                    if exe:
                        process_obj["exe"] = exe
                    if uid:
                        user_obj["uid"] = uid
                    if euid and euid != uid:
                        user_obj["euid"] = euid
                    if auid and auid not in ("4294967295", "-1"):
                        user_obj["auid"] = auid

                elif rec_type == "EXECVE":
                    argc = fields.get("argc", "0")
                    args = []
                    try:
                        for i in range(min(int(argc), 32)):
                            arg = fields.get(f"a{i}", "").strip('"')
                            if arg:
                                args.append(arg)
                    except (ValueError, KeyError):
                        pass
                    cmdline = " ".join(args)
                    audit["command_line"] = cmdline
                    msg_parts = [f"EXECVE {cmdline[:200]}"]
                    if args:
                        process_obj["name"] = args[0].split("/")[-1]
                        process_obj["command_line"] = cmdline
                        process_obj["args"] = args

                elif rec_type in (
                    "USER_LOGIN",
                    "USER_LOGOUT",
                    "USER_AUTH",
                    "USER_CMD",
                    "USER_CHAUTHTOK",
                    "ADD_USER",
                    "DEL_USER",
                    "LOGIN",
                    "LOGOUT",
                ):
                    acct = fields.get("acct", fields.get("id", "")).strip('"')
                    addr = fields.get("addr", "").strip('"')
                    exe = fields.get("exe", "").strip('"')
                    res = fields.get("res", fields.get("result", ""))
                    pid = fields.get("pid", "")

                    audit["result"] = res
                    if acct:
                        audit["acct"] = acct
                    if addr:
                        audit["addr"] = addr

                    msg_parts = [f"{rec_type}"]
                    if acct:
                        msg_parts.append(f"user={acct}")
                    if addr and addr not in ("?", "0.0.0.0"):
                        msg_parts.append(f"from={addr}")
                        network_obj["src_ip"] = addr
                    if res in ("failed", "failure"):
                        msg_parts.append("[FAILED]")

                    if acct:
                        user_obj["name"] = acct
                    if pid:
                        process_obj["pid"] = int(pid)

                elif rec_type == "AVC":
                    denied = "denied" in kv_str
                    comm = fields.get("comm", "").strip('"')
                    path_f = fields.get("path", "").strip('"')
                    tclass = fields.get("tclass", "")
                    perms = re.search(r"\{([^}]+)\}", kv_str)
                    perm_str = perms.group(1).strip() if perms else ""

                    audit["denied"] = denied
                    audit["comm"] = comm
                    audit["tclass"] = tclass
                    audit["perms"] = perm_str

                    action = "denied" if denied else "granted"
                    msg_parts = [f"SELinux/AppArmor {action}: {comm} {perm_str} on {path_f}"]
                    if comm:
                        process_obj["name"] = comm

                elif rec_type == "SECCOMP":
                    syscall = _syscall_name(fields.get("syscall", ""))
                    code = fields.get("code", "")
                    comm = fields.get("comm", "").strip('"')
                    pid = fields.get("pid", "")
                    audit["syscall"] = syscall
                    audit["comm"] = comm
                    msg_parts = [f"SECCOMP {syscall} blocked for {comm} (code={code})"]
                    if pid:
                        process_obj["pid"] = int(pid)
                    if comm:
                        process_obj["name"] = comm

                elif rec_type == "PATH":
                    item = fields.get("item", "")
                    name = fields.get("name", "").strip('"')
                    mode = fields.get("mode", "")
                    ouid = fields.get("ouid", "")
                    audit["path"] = name
                    audit["mode"] = mode
                    msg_parts = [f"PATH item={item} {name}"]

                elif rec_type == "PROCTITLE":
                    # hex-encoded or plain command line
                    title = fields.get("proctitle", "").strip('"')
                    # try hex decode
                    if re.match(r"^[0-9A-Fa-f]+$", title):
                        try:
                            title = (
                                bytes.fromhex(title)
                                .decode("utf-8", errors="replace")
                                .replace("\x00", " ")
                            )
                        except ValueError:
                            pass
                    audit["proctitle"] = title
                    msg_parts = [f"PROCTITLE {title[:200]}"]
                    if title:
                        process_obj["command_line"] = title

                else:
                    # Generic fallback — dump all kv as audit fields
                    audit.update({k: v for k, v in fields.items() if k not in ("type", "serial")})
                    res = fields.get("res", fields.get("result", ""))
                    if res:
                        audit["result"] = res
                    msg_parts = [rec_type]
                    if res in ("failed", "failure"):
                        msg_parts.append("[FAILED]")

                msg = " ".join(msg_parts)

                event: dict[str, Any] = {
                    "fo_id": str(uuid.uuid4()),
                    "timestamp": ts,
                    "timestamp_desc": "Audit Event",
                    "message": msg,
                    "artifact_type": "audit_event",
                    "audit": audit,
                    "raw": {"line": line},
                }

                if process_obj:
                    event["process"] = process_obj
                if user_obj:
                    event["user"] = user_obj
                if network_obj:
                    event["network"] = network_obj

                yield event

    def get_stats(self) -> dict[str, Any]:
        return {}
