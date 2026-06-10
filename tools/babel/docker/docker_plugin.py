"""
Docker Plugin — parses Docker daemon logs and container listing outputs.

Handles three formats:
  1. docker ps / docker ps -a tabular output
       CONTAINER ID   IMAGE    COMMAND   CREATED   STATUS   PORTS    NAMES
       abc123def456   nginx    "..."     2h ago    Up 2h    80/tcp   web

  2. docker ps --format '{{json .}}' (one JSON object per line)
       {"ID":"abc123","Image":"nginx:latest","Status":"Up 2 hours",...}

  3. Docker daemon logfmt (with or without syslog wrapper)
       time="2026-04-28T10:57:36Z" level=info msg="container started" container.id=abc
       Apr 28 10:57:36 host dockerd[1234]: time="..." level=info msg="..."

Emits artifact_type:
  docker_container — for container listing entries
  docker_event     — for daemon log lines

Priority 110 — above syslog (100) so docker.log is handled here instead
of falling through to the generic syslog parser.
"""

from __future__ import annotations

import json
import re
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

# ── Patterns ──────────────────────────────────────────────────────────────────

# docker ps table header
_PS_HEADER_RE = re.compile(r"^\s*CONTAINER\s+ID\s+IMAGE", re.IGNORECASE)

# logfmt key=value or key="quoted value"
_LOGFMT_PAIR_RE = re.compile(r'([\w./-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(\S+))')

# Syslog prefix: "Apr 28 10:57:36 host process[pid]: "
_SYSLOG_PREFIX_RE = re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:\s+")

# Docker daemon logfmt marker — must contain time= and msg=
_DAEMON_LOGFMT_RE = re.compile(r'time\s*=\s*"[^"]+"\s+level\s*=')

# ISO8601 / RFC3339 timestamp from logfmt time= field
_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$")

_KNOWN_NAMES = frozenset(
    {
        "docker.log",
        "docker_containers.log",
        "docker_ps.log",
        "containers.log",
        "docker_images.log",
        "docker_networks.log",
        "docker_volumes.log",
        "docker_inspect.log",
        "docker_stats.log",
        "docker_events.log",
        "containerd.log",
        "dockerd.log",
        "moby.log",
    }
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _parse_logfmt(line: str) -> dict[str, str]:
    """Parse logfmt key=value pairs from a line."""
    result: dict[str, str] = {}
    for m in _LOGFMT_PAIR_RE.finditer(line):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        result[key] = val
    return result


def _strip_syslog_prefix(line: str) -> str:
    """Remove RFC3164 syslog prefix if present."""
    m = _SYSLOG_PREFIX_RE.match(line)
    return line[m.end() :] if m else line


def _normalise_ts(raw: str) -> str:
    """Normalise an ISO8601 timestamp to YYYY-MM-DDTHH:MM:SSZ."""
    raw = raw.strip()
    m = _TS_RE.match(raw)
    if not m:
        return raw
    base = m.group(1).replace(" ", "T")
    tz = m.group(3) or "Z"
    if tz == "Z":
        return f"{base}Z"
    return f"{base}{tz}"


def _mtime_or_now(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _detect_format(path: Path) -> str | None:
    """Return 'ps_table', 'ps_json', 'daemon', or None."""
    try:
        with open(path, errors="replace") as fh:
            for _ in range(5):
                line = fh.readline()
                if not line:
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                if _PS_HEADER_RE.match(stripped):
                    return "ps_table"
                inner = _strip_syslog_prefix(stripped)
                if _DAEMON_LOGFMT_RE.search(inner):
                    return "daemon"
                try:
                    obj = json.loads(stripped)
                    if isinstance(obj, dict) and ("ID" in obj or "Names" in obj or "Image" in obj):
                        return "ps_json"
                except (json.JSONDecodeError, ValueError):
                    pass
    except OSError:
        pass
    return None


# ── Plugin ────────────────────────────────────────────────────────────────────


class DockerPlugin(BasePlugin):
    """Parses Docker container listings and daemon logs."""

    PLUGIN_NAME = "docker"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "docker_event"
    SUPPORTED_EXTENSIONS = [".log", ".txt"]
    SUPPORTED_MIME_TYPES = ["text/plain"]
    PLUGIN_PRIORITY = 110

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(_KNOWN_NAMES)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        if file_path.name.lower() in _KNOWN_NAMES:
            return True
        return _detect_format(file_path) is not None

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        fmt = _detect_format(path)
        if fmt == "ps_table":
            yield from self._parse_ps_table(path)
        elif fmt == "ps_json":
            yield from self._parse_ps_json(path)
        else:
            yield from self._parse_daemon(path)

    # ── docker ps tabular ─────────────────────────────────────────────────────

    def _parse_ps_table(self, path: Path) -> Generator[dict[str, Any], None, None]:
        snap_ts = _mtime_or_now(path)
        header_line = None
        col_starts: list[int] = []

        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open docker ps file: {exc}") from exc

        with fh:
            for raw in fh:
                line = raw.rstrip("\n")
                if _PS_HEADER_RE.match(line):
                    header_line = line
                    # Detect column start positions from the header
                    cols = re.finditer(r"\S+(?:\s+\S+)*", line)
                    col_starts = [m.start() for m in cols]
                    continue
                if header_line is None or not line.strip():
                    continue

                # Extract columns by position
                def _col(i: int) -> str:
                    start = col_starts[i] if i < len(col_starts) else 0
                    end = col_starts[i + 1] if i + 1 < len(col_starts) else len(line)
                    return line[start:end].strip()

                container_id = _col(0)
                image = _col(1)
                command = _col(2).strip('"')
                created = _col(3)
                status = _col(4)
                ports = _col(5)
                name = _col(6)

                if not container_id:
                    continue

                running = "up" in status.lower()
                msg = f"Container {name or container_id[:12]} [{image}] — {status}"

                event: dict[str, Any] = {
                    "timestamp": snap_ts,
                    "timestamp_desc": "Container Snapshot",
                    "message": msg,
                    "artifact_type": "docker_container",
                    "docker": {
                        "container_id": container_id,
                        "container_name": name,
                        "image": image,
                        "command": command,
                        "created": created,
                        "status": status,
                        "ports": ports,
                        "running": running,
                    },
                }
                yield event

    # ── docker ps --format '{{json .}}' ──────────────────────────────────────

    def _parse_ps_json(self, path: Path) -> Generator[dict[str, Any], None, None]:
        snap_ts = _mtime_or_now(path)
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open docker ps json file: {exc}") from exc

        with fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(obj, dict):
                    continue

                cid = obj.get("ID", obj.get("Id", ""))
                image = obj.get("Image", "")
                status = obj.get("Status", "")
                name = obj.get("Names", obj.get("Name", ""))
                ports = obj.get("Ports", "")
                cmd = obj.get("Command", "")

                running = "up" in status.lower()
                msg = f"Container {name or cid[:12]} [{image}] — {status}"

                event: dict[str, Any] = {
                    "timestamp": snap_ts,
                    "timestamp_desc": "Container Snapshot",
                    "message": msg,
                    "artifact_type": "docker_container",
                    "docker": {
                        "container_id": cid,
                        "container_name": name,
                        "image": image,
                        "command": cmd,
                        "status": status,
                        "ports": ports,
                        "running": running,
                    },
                    "raw": obj,
                }
                yield event

    # ── Docker daemon logfmt ──────────────────────────────────────────────────

    def _parse_daemon(self, path: Path) -> Generator[dict[str, Any], None, None]:
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open docker daemon log: {exc}") from exc

        fallback_ts = _mtime_or_now(path)

        with fh:
            for raw in fh:
                line = raw.rstrip("\n")
                if not line.strip():
                    continue

                inner = _strip_syslog_prefix(line)
                fields = _parse_logfmt(inner)
                if not fields:
                    continue

                ts_raw = fields.get("time", fields.get("ts", ""))
                ts = _normalise_ts(ts_raw) if ts_raw else fallback_ts
                level = fields.get("level", fields.get("severity", "info")).lower()
                msg = fields.get("msg", fields.get("message", inner[:200]))

                # Container-specific fields
                container_id = (
                    fields.get("container.id")
                    or fields.get("container_id")
                    or fields.get("containerId", "")
                )
                container_name = (
                    fields.get("container.name")
                    or fields.get("container_name")
                    or fields.get("name", "")
                )
                image = fields.get("image.name") or fields.get("image", "")
                error = fields.get("error", "")

                display = msg
                if container_name:
                    display = f"[{container_name}] {msg}"
                elif container_id:
                    display = f"[{container_id[:12]}] {msg}"

                event: dict[str, Any] = {
                    "timestamp": ts,
                    "timestamp_desc": "Docker Daemon Log",
                    "message": display,
                    "artifact_type": "docker_event",
                    "docker": {
                        "level": level,
                        "container_id": container_id,
                        "container_name": container_name,
                        "image": image,
                        **({} if not error else {"error": error}),
                    },
                }

                if error:
                    event["error"] = {"message": error}

                yield event

    def get_stats(self) -> dict[str, Any]:
        return {}
