"""
Kubernetes Resources Plugin — parses kubectl tabular and JSON output.

Handles output from common kubectl get commands:

  kubectl get pods [-o wide]     → k8s_pod
  kubectl get nodes [-o wide]    → k8s_node
  kubectl get services           → k8s_service
  kubectl get deployments        → k8s_deployment
  kubectl get namespaces         → k8s_namespace
  kubectl get events             → k8s_kube_event
  kubectl get replicasets        → k8s_replicaset
  kubectl get daemonsets         → k8s_daemonset
  kubectl get statefulsets       → k8s_statefulset
  kubectl get ingresses          → k8s_ingress
  kubectl get configmaps         → k8s_configmap
  kubectl get secrets            → k8s_secret
  kubectl get jobs               → k8s_job
  kubectl get cronjobs           → k8s_cronjob
  kubectl get persistentvolumes  → k8s_pv
  kubectl get pvc                → k8s_pvc

Detection: peeks at first line for known kubectl header patterns.
Each row becomes one event with a kubernetes.* sub-object.

Priority 108 — above syslog (100), below k3s (112) and docker (110).
"""

from __future__ import annotations

import json
import re
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

# ── Header patterns → (artifact_type, columns_we_care_about) ──────────────────

# Maps first-header-word (uppercase) → artifact_type
_HEADER_MAP: dict[str, str] = {
    "NAMESPACE": "k8s_pod",  # pods -o wide starts with NAMESPACE
    "NAME": "k8s_generic",  # fallback — many resources start NAME
    "STATUS": "k8s_node",  # nodes (NAME  STATUS  ROLES  AGE  VERSION)
    "TYPE": "k8s_service",  # services (NAME  TYPE  CLUSTER-IP  ...)
    "READY": "k8s_deployment",  # deployments (NAME  READY  UP-TO-DATE  ...)
    "LAST SEEN": "k8s_kube_event",  # events (LAST SEEN  TYPE  REASON  ...)
}

# Recognise kubectl headers by checking for specific column sets
_PODS_HEADER_RE = re.compile(r"^\s*NAME\s+READY\s+STATUS\s+RESTARTS", re.I)
_PODS_WIDE_HEADER_RE = re.compile(r"^\s*NAMESPACE\s+NAME\s+READY\s+STATUS\s+RESTARTS", re.I)
_NODES_HEADER_RE = re.compile(r"^\s*NAME\s+STATUS\s+ROLES\s+AGE\s+VERSION", re.I)
_SVC_HEADER_RE = re.compile(r"^\s*NAME\s+TYPE\s+CLUSTER-IP", re.I)
_DEPLOY_HEADER_RE = re.compile(r"^\s*NAME\s+READY\s+UP-TO-DATE\s+AVAILABLE", re.I)
_NS_HEADER_RE = re.compile(r"^\s*NAME\s+STATUS\s+AGE\s*$", re.I)
_EVENTS_HEADER_RE = re.compile(r"^\s*LAST\s+SEEN\s+TYPE\s+REASON", re.I)
_DS_HEADER_RE = re.compile(r"^\s*NAME\s+DESIRED\s+CURRENT\s+READY\s+UP-TO-DATE", re.I)
_SS_HEADER_RE = re.compile(r"^\s*NAME\s+READY\s+AGE\s*$", re.I)
_RS_HEADER_RE = re.compile(r"^\s*NAME\s+DESIRED\s+CURRENT\s+READY\s+AGE", re.I)
_INGRESS_HEADER_RE = re.compile(r"^\s*(?:CLASS\s+)?NAME.*HOSTS.*ADDRESS.*PORTS", re.I)
_PV_HEADER_RE = re.compile(r"^\s*NAME\s+CAPACITY\s+ACCESS", re.I)
_PVC_HEADER_RE = re.compile(r"^\s*NAME\s+STATUS\s+VOLUME\s+CAPACITY", re.I)
_CM_HEADER_RE = re.compile(r"^\s*NAME\s+DATA\s+AGE", re.I)
_SECRET_HEADER_RE = re.compile(r"^\s*NAME\s+TYPE\s+DATA\s+AGE", re.I)
_JOB_HEADER_RE = re.compile(r"^\s*NAME\s+COMPLETIONS\s+DURATION", re.I)
_CRONJOB_HEADER_RE = re.compile(r"^\s*NAME\s+SCHEDULE\s+SUSPEND", re.I)

_HEADER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (_PODS_WIDE_HEADER_RE, "k8s_pod"),
    (_PODS_HEADER_RE, "k8s_pod"),
    (_NODES_HEADER_RE, "k8s_node"),
    (_SVC_HEADER_RE, "k8s_service"),
    (_DEPLOY_HEADER_RE, "k8s_deployment"),
    (_EVENTS_HEADER_RE, "k8s_kube_event"),
    (_DS_HEADER_RE, "k8s_daemonset"),
    (_RS_HEADER_RE, "k8s_replicaset"),
    (_INGRESS_HEADER_RE, "k8s_ingress"),
    (_PV_HEADER_RE, "k8s_pv"),
    (_PVC_HEADER_RE, "k8s_pvc"),
    (_CM_HEADER_RE, "k8s_configmap"),
    (_SECRET_HEADER_RE, "k8s_secret"),
    (_JOB_HEADER_RE, "k8s_job"),
    (_CRONJOB_HEADER_RE, "k8s_cronjob"),
    (_NS_HEADER_RE, "k8s_namespace"),
]

_KNOWN_NAMES = frozenset(
    {
        "pods.log",
        "pods.txt",
        "kubectl_pods.log",
        "kubectl_get_pods.log",
        "nodes.log",
        "kubectl_nodes.log",
        "kubectl_get_nodes.log",
        "services.log",
        "kubectl_services.log",
        "kubectl_get_services.log",
        "deployments.log",
        "kubectl_deployments.log",
        "kubectl_get_deployments.log",
        "namespaces.log",
        "kubectl_namespaces.log",
        "kubectl_events.log",
        "k8s_events.log",
        "kube_events.log",
        "daemonsets.log",
        "statefulsets.log",
        "replicasets.log",
        "ingresses.log",
        "configmaps.log",
        "secrets.log",
        "jobs.log",
        "cronjobs.log",
        "pvs.log",
        "pvcs.log",
        "kubectl_get.log",
        "kubectl_describe.log",
        "k8s_resources.log",
        "cluster_resources.log",
        "cluster_info.log",
    }
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _mtime_or_now(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _split_by_header(header_line: str, data_line: str) -> dict[str, str]:
    """
    Split a kubectl data line using column start positions from the header.
    Returns {column_name: value, ...}.
    """
    cols: list[tuple[str, int]] = []
    for m in re.finditer(r"\S+(?:\s+\S+)*?(?=\s{2,}|\s*$)", header_line):
        cols.append((m.group(0).strip(), m.start()))

    result: dict[str, str] = {}
    for i, (col_name, start) in enumerate(cols):
        end = cols[i + 1][1] if i + 1 < len(cols) else len(data_line)
        val = data_line[start:end].strip() if start <= len(data_line) else ""
        result[col_name] = val
    return result


def _detect_resource_type(header_line: str) -> str | None:
    for pattern, atype in _HEADER_PATTERNS:
        if pattern.match(header_line):
            return atype
    return None


def _detect_format(path: Path) -> str | None:
    """Return 'table', 'json_lines', or None."""
    try:
        with open(path, errors="replace") as fh:
            for _ in range(5):
                line = fh.readline()
                if not line:
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                if _detect_resource_type(stripped) is not None:
                    return "table"
                try:
                    obj = json.loads(stripped)
                    if isinstance(obj, dict) and obj.get("kind"):
                        return "json_lines"
                except (json.JSONDecodeError, ValueError):
                    pass
    except OSError:
        pass
    return None


# ── Plugin ────────────────────────────────────────────────────────────────────


class K8sResourcesPlugin(BasePlugin):
    """Parses kubectl get tabular output into structured k8s resource events."""

    PLUGIN_NAME = "k8s_resources"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "k8s_generic"
    SUPPORTED_EXTENSIONS = [".log", ".txt"]
    SUPPORTED_MIME_TYPES = ["text/plain"]
    PLUGIN_PRIORITY = 108

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
        if fmt == "json_lines":
            yield from self._parse_json_lines(path)
        else:
            yield from self._parse_table(path)

    # ── kubectl tabular ───────────────────────────────────────────────────────

    def _parse_table(self, path: Path) -> Generator[dict[str, Any], None, None]:
        snap_ts = _mtime_or_now(path)
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open kubectl output: {exc}") from exc

        header_line: str | None = None
        resource_type: str | None = None
        current_ns: str = "default"

        with fh:
            for raw in fh:
                line = raw.rstrip("\n")
                stripped = line.strip()

                if not stripped:
                    continue

                # Namespace separator printed by kubectl get --all-namespaces
                if stripped.startswith("Namespace:") or stripped.startswith("---"):
                    continue

                detected = _detect_resource_type(stripped)
                if detected is not None:
                    header_line = line
                    resource_type = detected
                    continue

                if header_line is None:
                    continue

                cols = _split_by_header(header_line, line)
                if not cols:
                    continue

                name = (cols.get("NAME") or cols.get("name") or "").strip()
                ns = (cols.get("NAMESPACE") or cols.get("namespace") or current_ns).strip()
                if not name:
                    continue

                # Build kubernetes sub-object from all column values
                k8s: dict[str, str] = {
                    k.lower().replace("-", "_").replace(" ", "_"): v for k, v in cols.items() if v
                }
                k8s["resource_type"] = resource_type or "unknown"

                msg = self._build_message(resource_type or "unknown", name, ns, cols)

                event: dict[str, Any] = {
                    "timestamp": snap_ts,
                    "timestamp_desc": "Cluster Snapshot",
                    "message": msg,
                    "artifact_type": resource_type or "k8s_generic",
                    "kubernetes": k8s,
                }
                yield event

    def _build_message(self, rtype: str, name: str, ns: str, cols: dict[str, str]) -> str:
        status = (cols.get("STATUS") or cols.get("PHASE") or cols.get("READY") or "").strip()
        suffix = f" [{status}]" if status else ""
        if rtype == "k8s_pod":
            return f"Pod {ns}/{name}{suffix}"
        if rtype == "k8s_node":
            ver = cols.get("VERSION", "")
            return f"Node {name}{suffix}" + (f" v{ver}" if ver else "")
        if rtype == "k8s_service":
            svc_type = cols.get("TYPE", "").strip()
            cluster_ip = cols.get("CLUSTER-IP", "").strip()
            return f"Service {ns}/{name} [{svc_type}] {cluster_ip}"
        if rtype == "k8s_kube_event":
            reason = cols.get("REASON", "").strip()
            obj = cols.get("OBJECT", "").strip()
            return f"Event: {reason} — {obj}"
        if rtype in ("k8s_deployment", "k8s_daemonset", "k8s_statefulset", "k8s_replicaset"):
            return f"{rtype.split('_', 1)[1].title()} {ns}/{name}{suffix}"
        return f"{name} [{rtype.replace('k8s_', '')}]{suffix}"

    # ── JSON lines (kubectl get -o json | jq ...) ─────────────────────────────

    def _parse_json_lines(self, path: Path) -> Generator[dict[str, Any], None, None]:
        snap_ts = _mtime_or_now(path)
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open kubectl json output: {exc}") from exc

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

                kind = obj.get("kind", "Unknown")
                meta = obj.get("metadata", {}) or {}
                name = meta.get("name", "")
                ns = meta.get("namespace", "cluster-scoped")
                phase = (obj.get("status") or {}).get("phase", "")

                atype = f"k8s_{kind.lower()}"
                msg = f"{kind} {ns}/{name}" if ns != "cluster-scoped" else f"{kind} {name}"
                if phase:
                    msg += f" [{phase}]"

                event: dict[str, Any] = {
                    "timestamp": snap_ts,
                    "timestamp_desc": "Cluster Snapshot",
                    "message": msg,
                    "artifact_type": atype,
                    "kubernetes": {
                        "resource_type": kind.lower(),
                        "name": name,
                        "namespace": ns,
                        "phase": phase,
                    },
                    "raw": obj,
                }
                yield event

    def get_stats(self) -> dict[str, Any]:
        return {}
