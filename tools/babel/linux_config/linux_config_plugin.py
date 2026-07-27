"""
Linux/macOS Config Plugin — structured parsing of system configuration files.

Handles:
  /etc/passwd        → unix_user   (username, uid, gid, home, shell)
  /etc/shadow        → unix_user   (username, account status, last pwd change)
  /etc/group         → unix_group  (groupname, gid, members)
  /etc/gshadow       → unix_group
  /etc/hosts         → hosts_entry (ip, hostnames — critical for pivot analysis)
  /etc/sudoers       → sudoers_rule (subject, privilege spec, NOPASSWD flag)
  authorized_keys    → ssh_authorized_key (key_type, comment, inferred owner)
  known_hosts        → ssh_known_host (hostname, key_type)
  sshd_config / ssh_config → ssh_config (key, value directives)
  crontab / cron.d/* → cron_job   (schedule, user, command)
  .conf / .cfg / .ovpn / .ini → config_file (line-by-line text events)

Priority 120 — above syslog (100) and shell_history (110) so these files
are not swallowed by generic log parsers.
"""

from __future__ import annotations

import re
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

# Exact filenames (lowercase) this plugin owns
_FILENAME_HANDLERS: dict[str, str] = {
    "passwd": "_parse_passwd",
    "shadow": "_parse_shadow",
    "group": "_parse_group",
    "gshadow": "_parse_group",
    "hosts": "_parse_hosts",
    "sudoers": "_parse_sudoers",
    "authorized_keys": "_parse_authorized_keys",
    "authorized_keys2": "_parse_authorized_keys",
    "known_hosts": "_parse_known_hosts",
    "sshd_config": "_parse_ssh_config",
    "ssh_config": "_parse_ssh_config",
    "crontab": "_parse_crontab",
    # Mount table — a rogue NFS/SMB entry is how staged data leaves a host.
    "fstab": "_parse_fstab",
    "mtab": "_parse_fstab",
    # /proc/mounts — the live mount table, same 6-field shape as fstab. Talon
    # flattens the path to config/proc/mounts.
    "mounts": "_parse_fstab",
    # The classic userland-rootkit hook: any .so listed here is injected into
    # every dynamically linked process on the box.
    "ld.so.preload": "_parse_ld_preload",
}

# Shell startup files. Anything an attacker appends here re-executes on every
# interactive login, which makes them a first-class persistence artifact rather
# than ordinary config — hence a dedicated handler, not the generic text path.
_SHELL_RC_NAMES = frozenset(
    {
        ".bashrc",
        "bashrc",
        "bash.bashrc",
        ".bash_profile",
        "bash_profile",
        ".bash_login",
        ".bash_logout",
        ".profile",
        "profile",
        ".zshrc",
        "zshrc",
        ".zprofile",
        ".zshenv",
        ".zlogin",
        ".kshrc",
        ".cshrc",
        ".tcshrc",
        "csh.cshrc",
        ".config/fish/config.fish",
        "config.fish",
    }
)

# Directory path components that indicate a crontab-format file
_CRON_DIRS = frozenset(
    {"cron.d", "crontabs", "cron.hourly", "cron.daily", "cron.weekly", "cron.monthly"}
)

# Drop-in directories whose members share the parent file's format. Talon
# collects these verbatim (config/sudoers.d/<file>, config/sysctl.d/<file>), and
# a backdoor is far likelier to arrive as a new drop-in than as an edit to the
# main file — so the directory has to route as strongly as the filename does.
_DROPIN_DIRS: dict[str, str] = {
    "sudoers.d": "_parse_sudoers",
    "sysctl.d": "_parse_generic_config",
    "pam.d": "_parse_generic_config",
    "profile.d": "_parse_shell_rc",
}

# systemd units — the dominant Linux persistence mechanism. Talon collects them
# from persistence/systemd/, persistence/systemd_user/ and enabled-unit lists.
_SYSTEMD_UNIT_EXTS = frozenset(
    {".service", ".timer", ".socket", ".mount", ".path", ".target", ".automount"}
)

# Extensions that should be parsed as generic config files
_CONFIG_EXTS = frozenset({".conf", ".cfg", ".ovpn", ".ini", ".cnf", ".gitconfig", ".netrc"})

# Extensionless dotfiles Talon collects that are plain key/value config.
_DOTFILE_NAMES = frozenset({".gitconfig", ".git-credentials", ".netrc", ".npmrc", ".curlrc"})

# MIME types assigned by file_type.py routing
_OWN_MIMES = frozenset({"text/x-unix-config", "text/x-crontab"})


class LinuxConfigPlugin(BasePlugin):
    """Parses Linux/macOS system configuration, SSH artifacts, and cron jobs."""

    PLUGIN_NAME = "linux_config"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "config_file"
    SUPPORTED_EXTENSIONS = list(_CONFIG_EXTS)
    SUPPORTED_MIME_TYPES = list(_OWN_MIMES)
    PLUGIN_PRIORITY = 120

    @classmethod
    def _resolve_handler(cls, file_path: Path) -> str | None:
        """Pick the handler for *file_path*, or None if this plugin passes.

        Shared by :meth:`can_handle` and :meth:`parse` so the two can never
        disagree — a plugin that claims a file it then cannot dispatch yields
        zero events, which is indistinguishable from a clean parse.
        """
        name = file_path.name.lower()
        if name in _FILENAME_HANDLERS:
            return _FILENAME_HANDLERS[name]
        if name in _SHELL_RC_NAMES:
            return "_parse_shell_rc"
        if file_path.suffix.lower() in _SYSTEMD_UNIT_EXTS:
            return "_parse_systemd_unit"

        parts_lower = {p.lower() for p in file_path.parts}
        if parts_lower & _CRON_DIRS:
            return "_parse_crontab"
        for dirname, handler in _DROPIN_DIRS.items():
            if dirname in parts_lower:
                return handler

        if name in _DOTFILE_NAMES or file_path.suffix.lower() in _CONFIG_EXTS:
            return "_parse_generic_config"
        return None

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        if mime_type in _OWN_MIMES:
            return True
        return cls._resolve_handler(file_path) is not None

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        handler_name = self._resolve_handler(path) or "_parse_generic_config"
        yield from getattr(self, handler_name)(path)

    # ── File reader ───────────────────────────────────────────────────────────

    def _lines(self, path: Path) -> list[str]:
        try:
            return path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            raise PluginFatalError(f"Cannot read {path.name}: {exc}") from exc

    # ── /etc/passwd ───────────────────────────────────────────────────────────

    def _parse_passwd(self, path: Path) -> Generator[dict, None, None]:
        for line in self._lines(path):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            username, _, uid, gid, comment, home, shell = parts[:7]
            interactive = not any(
                s in shell for s in ("nologin", "false", "sync", "halt", "shutdown")
            )
            yield {
                "timestamp": None,
                "timestamp_desc": "User Account",
                "message": f"User: {username}  uid={uid}  shell={shell}",
                "artifact_type": "unix_user",
                "unix_user": {
                    "username": username,
                    "uid": uid,
                    "gid": gid,
                    "comment": comment,
                    "home": home,
                    "shell": shell,
                    "interactive": interactive,
                },
                "user": {"name": username, "id": uid},
                "raw": {"line": line},
            }

    # ── /etc/shadow ───────────────────────────────────────────────────────────

    def _parse_shadow(self, path: Path) -> Generator[dict, None, None]:
        epoch = datetime(1970, 1, 1, tzinfo=UTC)
        for line in self._lines(path):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
                continue
            username = parts[0]
            pwd_field = parts[1] if len(parts) > 1 else ""
            locked = pwd_field.startswith("!") or pwd_field in ("*", "!!", "")
            last_change_days = parts[2] if len(parts) > 2 else ""
            ts = None
            if last_change_days.isdigit():
                try:
                    ts = (epoch + timedelta(days=int(last_change_days))).isoformat()
                except (ValueError, OverflowError):
                    pass
            yield {
                "timestamp": ts,
                "timestamp_desc": "Password Last Changed",
                "message": f"User {username}: {'locked' if locked else 'active'}",
                "artifact_type": "unix_user",
                "unix_user": {
                    "username": username,
                    "account_locked": locked,
                    "password_last_changed": ts,
                },
                "user": {"name": username},
                "raw": {"line": line},
            }

    # ── /etc/group ────────────────────────────────────────────────────────────

    def _parse_group(self, path: Path) -> Generator[dict, None, None]:
        for line in self._lines(path):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 3:
                continue
            groupname, _, gid = parts[0], parts[1], parts[2]
            members = (
                [m.strip() for m in parts[3].split(",") if m.strip()] if len(parts) > 3 else []
            )
            yield {
                "timestamp": None,
                "timestamp_desc": "Group Definition",
                "message": f"Group: {groupname}  gid={gid}  members={','.join(members) or 'none'}",
                "artifact_type": "unix_group",
                "unix_group": {
                    "groupname": groupname,
                    "gid": gid,
                    "members": members,
                },
                "raw": {"line": line},
            }

    # ── /etc/hosts ────────────────────────────────────────────────────────────

    def _parse_hosts(self, path: Path) -> Generator[dict, None, None]:
        for line in self._lines(path):
            # Strip inline comments
            line = line.split("#")[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip, hostnames = parts[0], parts[1:]
            yield {
                "timestamp": None,
                "timestamp_desc": "Hosts Entry",
                "message": f"{ip} → {' '.join(hostnames)}",
                "artifact_type": "hosts_entry",
                "hosts_entry": {
                    "ip": ip,
                    "hostnames": hostnames,
                },
                "network": {
                    "src_ip": ip,
                    "hostname": hostnames[0] if hostnames else "",
                },
                "raw": {"line": line},
            }

    # ── /etc/sudoers ──────────────────────────────────────────────────────────

    _SUDOERS_IGNORE = re.compile(r"^(@include|Defaults|#)")

    def _parse_sudoers(self, path: Path) -> Generator[dict, None, None]:
        for line in self._lines(path):
            line = line.strip()
            if not line or self._SUDOERS_IGNORE.match(line):
                continue
            # User/group alias definitions and privilege rules
            if "=" not in line:
                continue
            subject = line.split()[0] if line.split() else ""
            nopasswd = "NOPASSWD" in line
            is_group = subject.startswith("%")
            yield {
                "timestamp": None,
                "timestamp_desc": "Sudoers Rule",
                "message": f"sudo rule: {line}",
                "artifact_type": "sudoers_rule",
                "sudoers_rule": {
                    "subject": subject,
                    "is_group": is_group,
                    "nopasswd": nopasswd,
                    "rule": line,
                },
                "user": {"name": subject.lstrip("%")},
                "raw": {"line": line},
            }

    # ── authorized_keys ───────────────────────────────────────────────────────

    def _parse_authorized_keys(self, path: Path) -> Generator[dict, None, None]:
        # Infer account owner from path (e.g. /home/alice/.ssh/authorized_keys)
        owner = ""
        for i, part in enumerate(path.parts):
            if part in ("home", "Users") and i + 1 < len(path.parts):
                owner = path.parts[i + 1]
                break
            if part == "root":
                owner = "root"

        for line in self._lines(path):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Optional options prefix before key-type — skip options if present
            parts = line.split()
            if not parts:
                continue
            # Detect key type token: starts with "sk-", "ecdsa-", "ssh-", etc.
            key_type_idx = next(
                (i for i, p in enumerate(parts) if p.startswith(("ssh-", "ecdsa-", "sk-"))),
                0,
            )
            key_type = parts[key_type_idx] if key_type_idx < len(parts) else parts[0]
            comment = parts[key_type_idx + 2] if key_type_idx + 2 < len(parts) else ""
            yield {
                "timestamp": None,
                "timestamp_desc": "Authorized SSH Key",
                "message": f"SSH authorized key ({key_type}) for '{owner or '?'}': {comment or '<no comment>'}",
                "artifact_type": "ssh_authorized_key",
                "ssh_authorized_key": {
                    "key_type": key_type,
                    "comment": comment,
                    "owner": owner,
                    "source_file": str(path),
                },
                "user": {"name": owner} if owner else {},
                "raw": {"line": line},
            }

    # ── known_hosts ───────────────────────────────────────────────────────────

    def _parse_known_hosts(self, path: Path) -> Generator[dict, None, None]:
        for line in self._lines(path):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            hostname, key_type = parts[0], parts[1]
            # Hashed known_hosts entries start with |1|
            is_hashed = hostname.startswith("|1|")
            display = "<hashed>" if is_hashed else hostname.split(",")[0]
            yield {
                "timestamp": None,
                "timestamp_desc": "Known SSH Host",
                "message": f"Known host: {display}  ({key_type})",
                "artifact_type": "ssh_known_host",
                "ssh_known_host": {
                    "hostname": hostname,
                    "key_type": key_type,
                    "is_hashed": is_hashed,
                },
                "network": {"hostname": display},
                "raw": {"line": line},
            }

    # ── sshd_config / ssh_config ─────────────────────────────────────────────

    def _parse_ssh_config(self, path: Path) -> Generator[dict, None, None]:
        for line in self._lines(path):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            key, value = parts[0], parts[1]
            yield {
                "timestamp": None,
                "timestamp_desc": "SSH Config Directive",
                "message": f"{key}: {value}",
                "artifact_type": "ssh_config",
                "ssh_config": {
                    "key": key,
                    "value": value,
                    "filename": path.name,
                },
                "raw": {"line": line},
            }

    # ── crontab / cron.d ─────────────────────────────────────────────────────

    def _parse_crontab(self, path: Path) -> Generator[dict, None, None]:
        """
        System crontabs (/etc/crontab, cron.d/*) have a user column:
          MIN HR DOM MON DOW USER COMMAND
        User crontabs (spool/cron/crontabs/<user>) omit the user column:
          MIN HR DOM MON DOW COMMAND
        """
        parts_lower = {p.lower() for p in path.parts}
        is_system = "cron.d" in parts_lower or path.name.lower() == "crontab"

        for line in self._lines(path):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Skip CRON_TZ / MAILTO / environment vars
            if "=" in line and not line.startswith("@") and not any(c in line[:10] for c in " \t"):
                continue

            event = self._parse_cron_line(line, path.name, is_system)
            if event:
                yield event

    def _parse_cron_line(self, line: str, source: str, is_system: bool) -> dict | None:
        # Handle @reboot, @daily, etc.
        if line.startswith("@"):
            tok = line.split(None, 2 if is_system else 1)
            schedule = tok[0]
            if is_system and len(tok) >= 3:
                cron_user, cmd = tok[1], tok[2]
            elif not is_system and len(tok) >= 2:
                cron_user, cmd = source, tok[1]
            else:
                return None
            return self._cron_event(schedule, cron_user, cmd, source)

        # Standard 5-field (+ optional user field) schedule
        tok = line.split(None, 6 if is_system else 5)
        if is_system and len(tok) >= 7:
            schedule = " ".join(tok[:5])
            cron_user, cmd = tok[5], tok[6]
        elif not is_system and len(tok) >= 6:
            schedule = " ".join(tok[:5])
            cron_user, cmd = source, tok[5]
        else:
            return None
        return self._cron_event(schedule, cron_user, cmd, source)

    def _cron_event(self, schedule: str, user: str, command: str, source: str) -> dict:
        return {
            "timestamp": None,
            "timestamp_desc": "Cron Job",
            "message": f"[cron/{user}] {command}",
            "artifact_type": "cron_job",
            "cron_job": {
                "schedule": schedule,
                "user": user,
                "command": command,
                "source": source,
            },
            "process": {
                "command_line": command,
                "name": command.split()[0].split("/")[-1] if command.split() else "",
            },
            "user": {"name": user},
            "raw": {"line": f"{schedule} {user} {command}"},
        }

    # ── /etc/fstab, /etc/mtab ────────────────────────────────────────────────

    def _parse_fstab(self, path: Path) -> Generator[dict, None, None]:
        """Mount table → one ``mount_entry`` per row.

        Flags network filesystems explicitly: an fstab line pointing at an
        attacker-controlled NFS/SMB share is a staging path for exfiltration,
        and it reads as ordinary config unless the type is called out.
        """
        network_types = {"nfs", "nfs4", "cifs", "smbfs", "sshfs", "ftpfs", "davfs", "glusterfs"}
        for line in self._lines(path):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            device, mountpoint, fstype = parts[0], parts[1], parts[2]
            options = parts[3] if len(parts) > 3 else ""
            is_network = fstype.lower() in network_types
            yield {
                "timestamp": None,
                "timestamp_desc": "Mount Table Entry",
                "message": (
                    f"{'NETWORK ' if is_network else ''}mount: {device} → {mountpoint} "
                    f"({fstype}) {options}"
                ),
                "artifact_type": "mount_entry",
                "mount_entry": {
                    "device": device,
                    "mountpoint": mountpoint,
                    "fstype": fstype,
                    "options": options,
                    "network_filesystem": is_network,
                },
                "raw": {"line": line},
            }

    # ── /etc/ld.so.preload ───────────────────────────────────────────────────

    def _parse_ld_preload(self, path: Path) -> Generator[dict, None, None]:
        """Every entry is injected into every dynamically linked process.

        A non-empty ld.so.preload on a compromised host is close to conclusive:
        it is the standard userland-rootkit hook (Diamorphine, bedevil, Symbiote)
        and has almost no legitimate system-wide use.
        """
        for line in self._lines(path):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for lib in line.split():
                yield {
                    "timestamp": None,
                    "timestamp_desc": "Preloaded Library",
                    "message": f"ld.so.preload injects {lib} into every dynamically linked process",
                    "artifact_type": "preload_library",
                    "preload_library": {"path": lib, "source": str(path.name)},
                    "raw": {"line": line},
                }

    # ── systemd units (.service / .timer / .socket / …) ──────────────────────

    def _parse_systemd_unit(self, path: Path) -> Generator[dict, None, None]:
        """Unit file → one ``systemd_unit`` event carrying its execution intent.

        One event per unit rather than per line: the forensic question is "what
        does this unit run, as whom, and when is it triggered", and that answer
        is spread across [Unit]/[Service]/[Install] sections.
        """
        directives: dict[str, list[str]] = {}
        section = ""
        for line in self._lines(path):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped[1:-1]
                continue
            if "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            directives.setdefault(f"{section}.{key.strip()}", []).append(value.strip())

        def first(*keys: str) -> str:
            for k in keys:
                if directives.get(k):
                    return directives[k][0]
            return ""

        exec_start = first("Service.ExecStart", "Service.ExecStartPre")
        # A unit with nothing to execute and no trigger is inert — emitting an
        # event for it would just be noise in the timeline.
        if not exec_start and not directives:
            return

        run_as = first("Service.User") or "root"
        unit_type = path.suffix.lstrip(".")
        yield {
            "timestamp": None,
            "timestamp_desc": "systemd Unit Definition",
            "message": (
                f"systemd {unit_type} '{path.name}' runs {exec_start or '(no ExecStart)'} "
                f"as {run_as}"
            ),
            "artifact_type": "systemd_unit",
            "systemd_unit": {
                "name": path.name,
                "unit_type": unit_type,
                "description": first("Unit.Description"),
                "exec_start": exec_start,
                "exec_stop": first("Service.ExecStop"),
                "user": run_as,
                "working_directory": first("Service.WorkingDirectory"),
                "restart": first("Service.Restart"),
                "wanted_by": first("Install.WantedBy"),
                "on_calendar": first("Timer.OnCalendar"),
                "on_boot_sec": first("Timer.OnBootSec"),
                "listen": first("Socket.ListenStream", "Socket.ListenDatagram"),
            },
            "process": {"command_line": exec_start} if exec_start else {},
            "user": {"name": run_as},
            "raw": {"directives": {k: v for k, v in directives.items()}},
        }

    # ── Shell startup files (.bashrc, /etc/profile.d/*, …) ───────────────────

    def _parse_shell_rc(self, path: Path) -> Generator[dict, None, None]:
        """Shell rc → one event per directive, with persistence-relevant kinds tagged.

        Every line here executes on login, so the interesting distinction is not
        "is this config" but "what does it do": an ``alias ls=`` that shadows a
        binary, a ``source`` of a file outside /etc, an inline ``eval`` of an
        encoded payload. The kind is surfaced so detections can key on it.
        """
        kinds = {
            "alias": "alias",
            "export": "env_export",
            "source": "source",
            ".": "source",
            "eval": "eval",
            "function": "function",
            "unset": "unset",
            "trap": "trap",
        }
        for lineno, raw_line in enumerate(self._lines(path), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            head = line.split(None, 1)[0].rstrip(";")
            kind = kinds.get(head, "command")
            yield {
                "timestamp": None,
                "timestamp_desc": "Shell Startup Directive",
                "message": f"{path.name}:{lineno} [{kind}] {line}",
                "artifact_type": "shell_rc_entry",
                "shell_rc_entry": {
                    "filename": path.name,
                    "line_number": lineno,
                    "kind": kind,
                    "directive": line,
                },
                "raw": {"line": raw_line},
            }

    # ── Generic config files (.conf, .cfg, .ovpn, .ini) ──────────────────────

    def _parse_generic_config(self, path: Path) -> Generator[dict, None, None]:
        ext = path.suffix.lower()
        atype = {
            ".ovpn": "vpn_config",
            ".conf": "config_file",
            ".cfg": "config_file",
            ".ini": "config_file",
            ".cnf": "config_file",
        }.get(ext, "config_file")

        for line in self._lines(path):
            line = line.strip()
            if not line or line.startswith(("#", ";", "//")):
                continue
            yield {
                "timestamp": None,
                "message": line,
                "artifact_type": atype,
                "config_file": {
                    "filename": path.name,
                    "line": line,
                },
            }

    def get_stats(self) -> dict[str, Any]:
        return {}
