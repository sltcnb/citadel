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

from babel.base_plugin import BasePlugin, PluginFatalError, PluginParseError

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
        # Names Talon actually writes (tools/talon/collect.py::_containers). The
        # ".log" set above was a convention this collector never followed — it
        # emits .json/.txt per runtime — so every container snapshot in a real
        # bundle used to fall through to the generic JSON fallback.
        "container_sockets.txt",
        *(
            f"{runtime}_{kind}"
            for runtime in ("docker", "podman")
            for kind in (
                "ps.json",
                "images.json",
                "networks.json",
                "volumes.json",
                "info.txt",
                "disk.txt",
            )
        ),
    }
)

# Talon writes one file per container into these subdirectories:
#   containers/inspect/<runtime>_<cid>.json   (full inspect record)
#   containers/logs/<runtime>_<cid>.txt       (captured stdout/stderr)
# The container id in the name makes an exact-name set impossible, so these are
# claimed by directory context instead.
_INSPECT_DIRS = frozenset({"inspect"})
_CONTAINER_LOG_DIRS = frozenset({"logs"})
_CONTAINER_PARENT_DIRS = frozenset({"containers"})


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


def _container_dir_kind(path: Path) -> str | None:
    """Classify a per-container file by the directory Talon placed it in."""
    parts = {p.lower() for p in path.parts}
    if not (parts & _CONTAINER_PARENT_DIRS):
        return None
    if parts & _INSPECT_DIRS:
        return "inspect"
    if parts & _CONTAINER_LOG_DIRS:
        return "container_log"
    return None


def _detect_format(path: Path) -> str | None:
    """Return 'ps_table', 'ps_json', 'inspect', 'json_file_log', 'daemon', or None."""
    # A whole-file JSON document (docker inspect) cannot be recognised from a
    # single line, so try it first — the array form spans the entire file.
    try:
        head = path.read_text(errors="replace")[:65536].lstrip()
    except OSError:
        head = ""
    if head.startswith("["):
        try:
            doc = json.loads(path.read_text(errors="replace"))
        except (json.JSONDecodeError, ValueError, OSError):
            doc = None
        if isinstance(doc, list) and doc and isinstance(doc[0], dict):
            if "Id" in doc[0] and ("Config" in doc[0] or "State" in doc[0]):
                return "inspect"

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
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(obj, dict):
                    continue
                # Docker's json-file logging driver: the container's own stdout.
                if "log" in obj and "stream" in obj and "time" in obj:
                    return "json_file_log"
                if "ID" in obj or "Names" in obj or "Image" in obj:
                    return "ps_json"
                if "Id" in obj and ("Config" in obj or "State" in obj):
                    return "inspect"
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
        if _container_dir_kind(file_path):
            return True
        return _detect_format(file_path) is not None

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        # Content detection first: it is authoritative. Directory context is the
        # fallback for the per-container files whose ids make names unmatchable.
        fmt = _detect_format(path) or _container_dir_kind(path)
        if fmt == "ps_table":
            yield from self._parse_ps_table(path)
        elif fmt == "ps_json":
            yield from self._parse_ps_json(path)
        elif fmt == "inspect":
            yield from self._parse_inspect(path)
        elif fmt == "json_file_log":
            yield from self._parse_json_file_log(path)
        elif path.name.lower() == "container_sockets.txt":
            yield from self._parse_sockets(path)
        else:
            yield from self._parse_daemon(path)

    # ── container runtime sockets ─────────────────────────────────────────────

    def _parse_sockets(self, path: Path) -> Generator[dict[str, Any], None, None]:
        """Which container runtime sockets exist on the host.

        Worth an event each: a reachable ``docker.sock`` is root-equivalent, and
        finding one bind-mounted into a container is the standard escape path — so
        its presence belongs on the timeline next to the container inventory,
        not buried in a text file. Talon writes one "Found: <path>" line per
        socket it saw.
        """
        snap_ts = _mtime_or_now(path)
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError as exc:
            raise PluginFatalError(f"Cannot read container sockets file: {exc}") from exc

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            # "Found: /var/run/docker.sock" — tolerate a bare path too.
            if stripped.lower().startswith("found:"):
                sock = stripped.split(":", 1)[1].strip()
            else:
                sock = stripped
            if not sock.startswith("/"):
                continue
            runtime = "docker"
            for candidate in ("podman", "containerd", "crio", "docker"):
                if candidate in sock:
                    runtime = candidate
                    break
            yield {
                "timestamp": snap_ts,
                "timestamp_desc": "Container Socket Present",
                "message": f"container runtime socket present: {sock} ({runtime})",
                "artifact_type": "container_socket",
                "docker": {"socket_path": sock, "runtime": runtime},
                "file": {"path": sock},
                "raw": {"line": line},
            }

    # ── docker inspect ────────────────────────────────────────────────────────

    def _parse_inspect(self, path: Path) -> Generator[dict[str, Any], None, None]:
        """``docker inspect`` → container lifecycle events.

        The inspect record is the densest container artifact in a bundle: it
        pins the image, the entrypoint actually executed, the host PID, mounted
        host paths (a container escape reads as a bind mount of ``/``), and the
        create/start/finish times. Emits one event per timestamp so each lands
        in the timeline at the moment it describes.
        """
        try:
            doc = json.loads(path.read_text(errors="replace"))
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            raise PluginParseError(f"Cannot parse docker inspect JSON: {exc}") from exc

        records = doc if isinstance(doc, list) else [doc]
        for rec in records:
            if not isinstance(rec, dict):
                continue
            cid = rec.get("Id", "")
            state = rec.get("State") or {}
            config = rec.get("Config") or {}
            host_config = rec.get("HostConfig") or {}
            name = str(rec.get("Name", "")).lstrip("/")
            image = config.get("Image") or rec.get("Image", "")
            cmd = config.get("Cmd")
            command = " ".join(cmd) if isinstance(cmd, list) else (cmd or "")
            entrypoint = config.get("Entrypoint")
            if isinstance(entrypoint, list):
                entrypoint = " ".join(entrypoint)

            mounts = [
                f"{m.get('Source', '')}:{m.get('Destination', '')}"
                for m in (rec.get("Mounts") or [])
                if isinstance(m, dict)
            ]
            base = {
                "container_id": cid,
                "container_name": name,
                "image": image,
                "command": command,
                "entrypoint": entrypoint or "",
                "status": state.get("Status", ""),
                "pid": state.get("Pid"),
                "exit_code": state.get("ExitCode"),
                "privileged": bool(host_config.get("Privileged")),
                "network_mode": host_config.get("NetworkMode", ""),
                "mounts": mounts,
                "running": state.get("Status", "").lower() == "running",
            }

            # One event per lifecycle timestamp the record carries.
            for field, desc in (
                ("Created", "Container Created"),
                (("State", "StartedAt"), "Container Started"),
                (("State", "FinishedAt"), "Container Finished"),
            ):
                if isinstance(field, tuple):
                    raw_ts = (rec.get(field[0]) or {}).get(field[1], "")
                else:
                    raw_ts = rec.get(field, "")
                if not raw_ts or str(raw_ts).startswith("0001-01-01"):
                    continue  # Docker's zero value for "never happened"
                yield {
                    "timestamp": _normalise_ts(str(raw_ts)),
                    "timestamp_desc": desc,
                    "message": (
                        f"{desc}: {name or cid[:12]} [{image}] "
                        f"{command or entrypoint or ''}".strip()
                    ),
                    "artifact_type": "docker_container",
                    "docker": dict(base),
                    "process": {"command_line": command, "pid": state.get("Pid")},
                    "raw": rec,
                }

    # ── container stdout/stderr (json-file logging driver) ────────────────────

    def _parse_json_file_log(self, path: Path) -> Generator[dict[str, Any], None, None]:
        """The container's own output, one event per emitted line.

        This is the application's log — often the only record of what a
        compromised container actually did, since the image itself is immutable
        and the writable layer may be gone.
        """
        # containers/logs/<runtime>_<cid>.txt — recover the id from the name.
        stem = path.stem
        cid = stem.split("_", 1)[1] if "_" in stem else stem

        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open container log: {exc}") from exc

        fallback_ts = _mtime_or_now(path)
        with fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(obj, dict):
                    continue
                text = str(obj.get("log", "")).rstrip("\n")
                if not text:
                    continue
                stream = obj.get("stream", "stdout")
                yield {
                    "timestamp": _normalise_ts(str(obj.get("time", ""))) or fallback_ts,
                    "timestamp_desc": "Container Output",
                    "message": f"[{cid[:12]}/{stream}] {text}",
                    "artifact_type": "docker_log",
                    "docker": {"container_id": cid, "stream": stream},
                    "raw": obj,
                }

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
