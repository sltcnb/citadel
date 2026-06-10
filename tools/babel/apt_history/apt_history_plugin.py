"""APT history log parser — /var/log/apt/history.log[.N][.gz].

Each block records one package-management operation (install / upgrade / remove
/ purge / downgrade) with a Start-Date, the invoking command line, the affected
packages and an End-Date. One block → one timeline event, which is exactly what
an investigator wants: "what changed on this host, when, and who triggered it."
"""
from __future__ import annotations

import re
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError, iso_z

_FIELD = re.compile(r"^([A-Za-z-]+):\s*(.*)$")
_ACTIONS = ("Install", "Upgrade", "Remove", "Purge", "Downgrade", "Reinstall")
# A package list entry: "nginx:amd64 (1.24.0-2ubuntu7.8, 1.24.0-2ubuntu7.9)"
_PKG = re.compile(r"([^\s(,:]+)(?::\w+)?\s*\(([^)]*)\)")


def _open_text(path: Path):
    if path.name.lower().endswith(".gz"):
        import gzip

        return gzip.open(path, "rt", errors="replace")
    return open(path, errors="replace")


def _norm_date(s: str) -> str:
    # "2026-06-02  06:27:19" → "2026-06-02T06:27:19"
    return iso_z(re.sub(r"\s+", "T", s.strip(), count=1))


def _pkg_names(value: str) -> list[str]:
    return [m.group(1) for m in _PKG.finditer(value)] or [
        p.strip() for p in value.split(",") if p.strip()
    ]


class AptHistoryPlugin(BasePlugin):
    """Parses APT history.log block records into package-management events."""

    PLUGIN_NAME = "apt_history"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "package_event"
    SUPPORTED_EXTENSIONS = [".log"]
    SUPPORTED_MIME_TYPES = ["text/plain"]
    PLUGIN_PRIORITY = 60  # beats syslog/timestamped/json_file for apt history

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._parsed = 0

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        # Claim by content: an apt history block opens with "Start-Date:".
        try:
            with _open_text(file_path) as fh:
                for _ in range(20):
                    line = fh.readline()
                    if not line:
                        break
                    if line.startswith("Start-Date:"):
                        return True
        except OSError:
            pass
        return False

    def _emit(self, block: dict, path: Path) -> dict | None:
        if not block:
            return None
        actions = {k: v for k, v in block.items() if k in _ACTIONS and v}
        if not actions and "Error" not in block:
            return None  # not an operation block (e.g. trailing junk)
        cmd = block.get("Commandline", "")
        by = block.get("Requested-By", "")
        # Build a readable summary across all action types in the block.
        parts = []
        pkgs_all: list[str] = []
        for act, val in actions.items():
            names = _pkg_names(val)
            pkgs_all += names
            head = ", ".join(names[:3]) + (f" (+{len(names) - 3} more)" if len(names) > 3 else "")
            parts.append(f"{act}: {head}")
        verb = " · ".join(parts) if parts else f"Error: {block.get('Error', '')}"
        actor = f" by {by}" if by else (f" via {cmd.split()[0].rsplit('/', 1)[-1]}" if cmd else "")
        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": "package_event",
            "timestamp": _norm_date(block.get("Start-Date", "")) or None,
            "timestamp_desc": "Operation Start",
            "message": f"apt {verb}{actor}",
            "process": {"command_line": cmd} if cmd else None,
            "package_event": {
                "actions": list(actions.keys()),
                "packages": pkgs_all[:50],
                "package_count": len(pkgs_all),
                "commandline": cmd,
                "requested_by": by,
                "end_date": block.get("End-Date", ""),
                "error": block.get("Error", ""),
            },
            "raw": dict(block),
        }

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            fh = _open_text(path)
        except OSError as exc:
            raise PluginFatalError(f"Cannot open apt history: {exc}") from exc

        block: dict = {}
        with fh:
            for raw in fh:
                line = raw.rstrip("\n")
                if not line.strip():
                    evt = self._emit(block, path)
                    if evt:
                        self._parsed += 1
                        yield evt
                    block = {}
                    continue
                m = _FIELD.match(line)
                if m:
                    block[m.group(1)] = m.group(2)
            evt = self._emit(block, path)
            if evt:
                self._parsed += 1
                yield evt

    def get_stats(self) -> dict[str, Any]:
        return {"records_parsed": self._parsed}
