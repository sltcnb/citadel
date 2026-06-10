"""
CRI-CTL Plugin — parses crictl (Container Runtime Interface CLI) output.

Handles output from crictl commands commonly collected during Linux/Kubernetes
triage:

  crictl pods             → k8s_pod        (pod sandbox listing)
  crictl ps [-a]          → k8s_container  (container listing)
  crictl images           → k8s_image      (image listing)
  crictl info             → k8s_runtime    (runtime info)
  crictl stats            → k8s_container_stats

Detection: checks for crictl-specific column headers (POD ID, SANDBOX ID, IMAGE ID).
Falls back to tabular format heuristics.

Priority 106 — above syslog (100), below docker (110) and k3s (112).
"""

from __future__ import annotations

import re
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

# ── Header patterns ────────────────────────────────────────────────────────────

_PODS_HEADER_RE = re.compile(r"^\s*POD\s+ID\s+CREATED\s+STATE\s+NAME", re.I)
_PS_HEADER_RE = re.compile(r"^\s*CONTAINER\s+IMAGE\s+CREATED\s+STATE\s+NAME", re.I)
_IMAGES_HEADER_RE = re.compile(r"^\s*IMAGE\s+TAG\s+IMAGE\s+ID\s+SIZE", re.I)
_IMAGES2_HEADER_RE = re.compile(r"^\s*IMAGE\s+ID\s+REPODIGEST", re.I)
_STATS_HEADER_RE = re.compile(r"^\s*CONTAINER\s+CPU\s+%\s+MEM", re.I)

# Alternate crictl ps header (some versions)
_PS2_HEADER_RE = re.compile(r"^\s*CONTAINER\s+ID\s+IMAGE\s+COMMAND\s+CREATED", re.I)

_HEADER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (_PODS_HEADER_RE, "k8s_pod"),
    (_PS_HEADER_RE, "k8s_container"),
    (_PS2_HEADER_RE, "k8s_container"),
    (_IMAGES_HEADER_RE, "k8s_image"),
    (_IMAGES2_HEADER_RE, "k8s_image"),
    (_STATS_HEADER_RE, "k8s_container_stats"),
]

_KNOWN_NAMES = frozenset(
    {
        "crictl_pods.log",
        "crictl_ps.log",
        "crictl_containers.log",
        "crictl_images.log",
        "crictl_info.log",
        "crictl_stats.log",
        "crictl.log",
        "cri_pods.log",
        "cri_containers.log",
        "cri_images.log",
        "sandboxes.log",
        "pod_sandboxes.log",
    }
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _mtime_or_now(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _split_columns(header_line: str, data_line: str) -> dict[str, str]:
    """Split a crictl data line by column positions derived from the header."""
    cols: list[tuple[str, int]] = []
    for m in re.finditer(r"\S+(?:\s+\S+)*?(?=\s{2,}|\s*$)", header_line):
        cols.append((m.group(0).strip(), m.start()))

    result: dict[str, str] = {}
    for i, (name, start) in enumerate(cols):
        end = cols[i + 1][1] if i + 1 < len(cols) else len(data_line)
        result[name] = data_line[start:end].strip() if start <= len(data_line) else ""
    return result


def _detect_resource(header_line: str) -> str | None:
    for pat, atype in _HEADER_PATTERNS:
        if pat.match(header_line):
            return atype
    return None


def _detect_format(path: Path) -> bool:
    try:
        with open(path, errors="replace") as fh:
            for _ in range(5):
                line = fh.readline()
                if not line:
                    break
                stripped = line.strip()
                if _detect_resource(stripped) is not None:
                    return True
    except OSError:
        pass
    return False


# ── Plugin ────────────────────────────────────────────────────────────────────


class CrictlPlugin(BasePlugin):
    """Parses crictl pod, container, and image listing outputs."""

    PLUGIN_NAME = "crictl"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "k8s_container"
    SUPPORTED_EXTENSIONS = [".log", ".txt"]
    SUPPORTED_MIME_TYPES = ["text/plain"]
    PLUGIN_PRIORITY = 106

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
        snap_ts = _mtime_or_now(path)
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open crictl output: {exc}") from exc

        header_line: str | None = None
        resource_type: str | None = None

        with fh:
            for raw in fh:
                line = raw.rstrip("\n")
                stripped = line.strip()
                if not stripped:
                    continue

                detected = _detect_resource(stripped)
                if detected is not None:
                    header_line = line
                    resource_type = detected
                    continue

                if header_line is None or resource_type is None:
                    continue

                cols = _split_columns(header_line, line)
                if not cols:
                    continue

                yield self._make_event(snap_ts, resource_type, cols)

    def _make_event(
        self,
        ts: str,
        rtype: str,
        cols: dict[str, str],
    ) -> dict[str, Any]:
        k8s: dict[str, str] = {
            k.lower().replace(" ", "_").replace("-", "_"): v for k, v in cols.items() if v
        }
        k8s["resource_type"] = rtype

        if rtype == "k8s_pod":
            pod_id = cols.get("POD ID", cols.get("POD", ""))
            name = cols.get("NAME", "")
            ns = cols.get("NAMESPACE", "default")
            state = cols.get("STATE", "")
            pod_name = cols.get("POD", name)
            msg = f"Pod sandbox {ns}/{pod_name} [{state}]"
            k8s.update({"pod": pod_name, "namespace": ns, "state": state})

        elif rtype == "k8s_container":
            cid = cols.get("CONTAINER", "")[:12]
            name = cols.get("NAME", cid)
            image = cols.get("IMAGE", "")
            state = cols.get("STATE", "")
            pod = cols.get("POD", "")
            ns = cols.get("NAMESPACE", "")
            msg = f"Container {name} [{image}] — {state}"
            if pod:
                msg += f" in {ns}/{pod}"
            k8s.update({"container": name, "image": image, "state": state})
            if pod:
                k8s["pod"] = pod
            if ns:
                k8s["namespace"] = ns

        elif rtype == "k8s_image":
            image = cols.get("IMAGE", "")
            tag = cols.get("TAG", "latest")
            img_id = cols.get("IMAGE ID", "")[:12]
            size = cols.get("SIZE", "")
            msg = f"Image {image}:{tag} [{img_id}] {size}"
            k8s.update({"image": f"{image}:{tag}", "image_id": img_id})

        elif rtype == "k8s_container_stats":
            cid = cols.get("CONTAINER", "")[:12]
            cpu = cols.get("CPU %", cols.get("CPU", ""))
            mem = cols.get("MEM", cols.get("MEMORY", ""))
            name = cols.get("NAME", cid)
            msg = f"Container {name} CPU={cpu} MEM={mem}"

        else:
            name = next(iter(cols.values()), "unknown")
            msg = f"{rtype.replace('k8s_', '').title()} {name}"

        return {
            "timestamp": ts,
            "timestamp_desc": "Container Runtime Snapshot",
            "message": msg,
            "artifact_type": rtype,
            "kubernetes": k8s,
        }

    def get_stats(self) -> dict[str, Any]:
        return {}
