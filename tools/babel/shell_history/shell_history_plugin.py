"""
Shell History Plugin — parses command-line history files.

Supported formats:
  bash_history / .history — plain commands, optional #TIMESTAMP prefix lines
  zsh_history             — ": EPOCH:ELAPSED;COMMAND" extended format or plain
  fish_history            — YAML-like "- cmd: ...\n  when: EPOCH" blocks
  CONSOLEHOST_HISTORY.TXT — PowerShell plain command history (one cmd per line)

artifact_type: "shell_history"
PLUGIN_PRIORITY: 110  — claimed before syslog (100) so these files don't land
                         as generic syslog events.
"""

from __future__ import annotations

import re
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

# Handled file names (case-insensitive lookup done by loader)
_HANDLED = frozenset(
    {
        ".bash_history",
        ".zsh_history",
        ".history",
        ".local/share/fish/fish_history",  # path-based — caught by can_handle
        "consolehost_history.txt",
    }
)

# Exact base names that map to a shell type
_SHELL_MAP = {
    ".bash_history": "bash",
    ".zsh_history": "zsh",
    ".history": "sh",
    "consolehost_history.txt": "powershell",
    "fish_history": "fish",
}

# zsh extended history: ": EPOCH:ELAPSED;CMD"
_ZSH_EXT_RE = re.compile(r"^: (\d+):\d+;(.*)")

# bash timestamp header: "#EPOCH"
_BASH_TS_RE = re.compile(r"^#(\d+)$")


def _epoch_to_iso(epoch: int | str) -> str:
    try:
        return datetime.fromtimestamp(int(epoch), tz=UTC).isoformat()
    except (ValueError, OSError, OverflowError):
        return ""


class ShellHistoryPlugin(BasePlugin):
    """Parses bash, zsh, fish, PowerShell command history files."""

    PLUGIN_NAME = "shell_history"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "shell_history"
    SUPPORTED_EXTENSIONS = []
    SUPPORTED_MIME_TYPES = ["text/x-shell-history"]
    PLUGIN_PRIORITY = 110  # above syslog (100)

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return [
            ".bash_history",
            ".zsh_history",
            ".history",
            "fish_history",
            "CONSOLEHOST_HISTORY.TXT",
        ]

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        name_lower = file_path.name.lower()
        # Direct filename match
        if name_lower in {n.lower() for n in cls.get_handled_filenames()}:
            return True
        # fish_history lives inside a path — match by name regardless of path
        if name_lower == "fish_history":
            return True
        return False

    def _shell_type(self) -> str:
        return _SHELL_MAP.get(self.ctx.source_file_path.name.lower(), "shell")

    def setup(self) -> None:
        if not self.ctx.source_file_path.exists():
            raise PluginFatalError(f"File not found: {self.ctx.source_file_path}")

    def parse(self) -> Generator[dict[str, Any], None, None]:
        shell = self._shell_type()
        if shell == "fish":
            yield from self._parse_fish()
        elif shell == "zsh":
            yield from self._parse_zsh()
        elif shell == "bash":
            yield from self._parse_bash()
        else:
            yield from self._parse_plain(shell)

    # ── Format-specific parsers ───────────────────────────────────────────────

    def _parse_plain(self, shell: str) -> Generator[dict, None, None]:
        """Plain one-command-per-line (PowerShell, sh)."""
        path = self.ctx.source_file_path
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            raise PluginFatalError(f"Cannot read {path}: {exc}") from exc
        for i, cmd in enumerate(lines, 1):
            cmd = cmd.strip()
            if not cmd:
                continue
            yield self._event(cmd, shell, None, i)

    def _parse_bash(self) -> Generator[dict, None, None]:
        """bash_history — optional #TIMESTAMP header lines."""
        path = self.ctx.source_file_path
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            raise PluginFatalError(f"Cannot read {path}: {exc}") from exc

        pending_ts: str | None = None
        lineno = 0
        for line in lines:
            m = _BASH_TS_RE.match(line)
            if m:
                pending_ts = _epoch_to_iso(m.group(1))
                continue
            cmd = line.strip()
            if not cmd:
                pending_ts = None
                continue
            lineno += 1
            yield self._event(cmd, "bash", pending_ts, lineno)
            pending_ts = None

    def _parse_zsh(self) -> Generator[dict, None, None]:
        """zsh extended history OR plain format."""
        path = self.ctx.source_file_path
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            raise PluginFatalError(f"Cannot read {path}: {exc}") from exc

        lineno = 0
        for line in lines:
            m = _ZSH_EXT_RE.match(line)
            if m:
                ts = _epoch_to_iso(m.group(1))
                cmd = m.group(2).strip()
            else:
                ts = None
                cmd = line.strip()
            if not cmd:
                continue
            lineno += 1
            yield self._event(cmd, "zsh", ts, lineno)

    def _parse_fish(self) -> Generator[dict, None, None]:
        """fish_history: YAML-like blocks: '- cmd: ...\n  when: EPOCH'"""
        path = self.ctx.source_file_path
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot read {path}: {exc}") from exc

        # Split on "- cmd:" blocks
        blocks = re.split(r"^- cmd:", text, flags=re.MULTILINE)
        lineno = 0
        for block in blocks:
            if not block.strip():
                continue
            lines = block.splitlines()
            cmd = lines[0].strip() if lines else ""
            ts = None
            for l in lines[1:]:
                wm = re.match(r"\s*when:\s*(\d+)", l)
                if wm:
                    ts = _epoch_to_iso(wm.group(1))
                    break
            if not cmd:
                continue
            lineno += 1
            yield self._event(cmd, "fish", ts, lineno)

    # ── Event builder ─────────────────────────────────────────────────────────

    def _event(self, cmd: str, shell: str, ts: str | None, line: int) -> dict:
        return {
            "timestamp": ts,
            "timestamp_desc": "Command Executed",
            "message": cmd,
            "artifact_type": "shell_history",
            "process": {
                "command_line": cmd,
                "name": cmd.split()[0].split("/")[-1] if cmd.split() else "",
            },
            "shell_history": {
                "command": cmd,
                "shell": shell,
                "line_no": line,
            },
            "raw": {"line": cmd},
        }

    def get_stats(self) -> dict[str, Any]:
        return {}
