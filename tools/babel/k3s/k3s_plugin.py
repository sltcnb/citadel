"""
K3s / Kubernetes Log Plugin — parses structured k3s and kubelet log output.

Handles three common formats produced by k3s, kubelet, kube-apiserver, and
other Kubernetes control-plane components:

  1. Logfmt (Go standard library slog / logrus):
       time="2026-04-28T10:57:36Z" level=info msg="Starting controller" component=kubelet

  2. Syslog-wrapped logfmt (journald export):
       Apr 28 10:57:36 hostname k3s[1234]: time="..." level=info msg="..."

  3. JSON structured lines (klog v2 / zap):
       {"time":"2026-04-28T10:57:36Z","level":"info","msg":"Starting","component":"kubelet"}

For each line the plugin emits structured fields:
  kubernetes.level, kubernetes.component, kubernetes.namespace, kubernetes.pod,
  kubernetes.node, kubernetes.container, kubernetes.image, kubernetes.reason,
  kubernetes.object_kind, kubernetes.object_name

Priority 112 — above syslog (100) so k3s.log / kubelet.log are parsed here
instead of being treated as generic syslog, which loses all structured fields.
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

# logfmt key=value or key="quoted"
_LOGFMT_PAIR_RE = re.compile(r'([\w./-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(\S+))')

# Syslog RFC3164 prefix
_SYSLOG_PREFIX_RE = re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:\s+")

# k3s/kubelet logfmt marker
_K3S_LOGFMT_RE = re.compile(r'time\s*=\s*"[^"]+"\s+level\s*=')

# klog v1/v2 format: E0410 02:56:03.190991  528708 pod_workers.go:1324] body
_KLOG_RE = re.compile(
    r"^([IWEF])(\d{4})\s+"  # level char + MMDD date
    r"(\d{2}:\d{2}:\d{2}\.\d+)\s+"  # HH:MM:SS.microseconds
    r"(\d+)\s+"  # PID (may have extra leading spaces)
    r"([\w./_-]+):(\d+)\]\s*"  # file.go:line]
    r"(.*)"  # body (may be empty)
)

_KLOG_LEVELS = {"I": "info", "W": "warning", "E": "error", "F": "fatal"}

# klog v2 structured body: "quoted message" key="value" key2="value2"
# The leading quoted string is the human message; rest are typed key=value pairs.
_KLOG_MSG_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"')
# key=value where value may contain escaped quotes
_KLOG_KV_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')

# ISO timestamp normalisation
_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$")

_KNOWN_NAMES = frozenset(
    {
        "k3s.log",
        "k3s-server.log",
        "k3s-agent.log",
        "kubelet.log",
        "kube-apiserver.log",
        "kube-controller-manager.log",
        "kube-scheduler.log",
        "kube-proxy.log",
        "k8s.log",
        "kubernetes.log",
        "etcd.log",
        "containerd.log",
        "crio.log",
        "flannel.log",
        "calico.log",
        "coredns.log",
        "traefik.log",
        "rancher.log",
        "rke2.log",
    }
)

# Known k3s/kube field names → canonical key
_FIELD_MAP = {
    # pod
    "pod": "pod",
    "podName": "pod",
    "pod_name": "pod",
    # namespace
    "namespace": "namespace",
    "ns": "namespace",
    # node
    "node": "node",
    "nodeName": "node",
    "node_name": "node",
    # container
    "container": "container",
    "containerName": "container",
    # image
    "image": "image",
    "imageName": "image",
    # component
    "component": "component",
    "comp": "component",
    # reason/event
    "reason": "reason",
    # object
    "kind": "object_kind",
    "name": "object_name",
    # error
    "err": "error",
    "error": "error",
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _parse_logfmt(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for m in _LOGFMT_PAIR_RE.finditer(line):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        result[key] = val
    return result


def _strip_syslog_prefix(line: str) -> str:
    m = _SYSLOG_PREFIX_RE.match(line)
    return line[m.end() :] if m else line


def _normalise_ts(raw: str) -> str:
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


def _parse_klog_body(body: str) -> tuple[str, dict[str, str]]:
    """
    Parse a klog v2 message body.

    Two patterns:
      v2 structured:  "Error syncing pod" err="..." pod="ns/name"
      v1 plain text:  Error syncing pod, skipping

    Returns (human_message, {raw_key: raw_value}).
    """
    body = body.strip()
    if not body:
        return "", {}

    m = _KLOG_MSG_RE.match(body)
    if m:
        # v2: extract quoted message, then parse remaining key=value pairs
        msg = m.group(1).replace('\\"', '"')
        rest = body[m.end() :]
        raw_kv = {k: v.replace('\\"', '"') for k, v in _KLOG_KV_RE.findall(rest)}
    else:
        # v1: plain text body — try to parse trailing key=value pairs anyway
        raw_kv = {k: v.replace('\\"', '"') for k, v in _KLOG_KV_RE.findall(body)}
        # Strip extracted kv from message
        plain_end = (
            body.find(" " + list(_KLOG_KV_RE.findall(body)[0])[0] + "=")
            if raw_kv and _KLOG_KV_RE.search(body)
            else -1
        )
        msg = body[:plain_end].strip() if plain_end > 0 else body

    return msg, raw_kv


def _split_pod_ref(ref: str) -> tuple[str, str]:
    """Split 'namespace/podname' → (namespace, pod). Pass-through if no slash."""
    if "/" in ref:
        ns, pod = ref.split("/", 1)
        return ns.strip(), pod.strip()
    return "", ref.strip()


def _extract_k8s_fields(fields: dict[str, str]) -> dict[str, str]:
    """Map raw logfmt fields to canonical kubernetes.* sub-fields."""
    out: dict[str, str] = {}
    for src_key, dst_key in _FIELD_MAP.items():
        if src_key in fields and fields[src_key]:
            out[dst_key] = fields[src_key]
    return out


def _detect_format(path: Path) -> str | None:
    """Return 'logfmt', 'json', 'klog', or None."""
    try:
        with open(path, errors="replace") as fh:
            for _ in range(10):
                line = fh.readline()
                if not line:
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                inner = _strip_syslog_prefix(stripped)
                if _K3S_LOGFMT_RE.search(inner):
                    return "logfmt"
                if _KLOG_RE.match(stripped):
                    return "klog"
                try:
                    obj = json.loads(stripped)
                    if (
                        isinstance(obj, dict)
                        and ("time" in obj or "ts" in obj or "timestamp" in obj)
                        and ("msg" in obj or "message" in obj)
                    ):
                        return "json"
                except (json.JSONDecodeError, ValueError):
                    pass
    except OSError:
        pass
    return None


# ── Plugin ────────────────────────────────────────────────────────────────────


class K3sPlugin(BasePlugin):
    """Parses k3s / Kubernetes structured log lines into normalised events."""

    PLUGIN_NAME = "k3s"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "k8s_event"
    SUPPORTED_EXTENSIONS = [".log"]
    SUPPORTED_MIME_TYPES = ["text/plain"]
    PLUGIN_PRIORITY = 112

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
        fmt = _detect_format(path) or "logfmt"
        if fmt == "json":
            yield from self._parse_json(path)
        elif fmt == "klog":
            yield from self._parse_klog(path)
        else:
            yield from self._parse_logfmt(path)

    # ── logfmt / syslog-wrapped logfmt ───────────────────────────────────────

    def _parse_logfmt(self, path: Path) -> Generator[dict[str, Any], None, None]:
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open k3s log: {exc}") from exc

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
                msg = fields.get("msg", fields.get("message", inner[:300]))

                k8s_fields = _extract_k8s_fields(fields)
                error_val = fields.get("error", fields.get("err", ""))

                # Build a human-readable display
                display = msg
                if k8s_fields.get("namespace") and k8s_fields.get("pod"):
                    display = f"[{k8s_fields['namespace']}/{k8s_fields['pod']}] {msg}"
                elif k8s_fields.get("component"):
                    display = f"[{k8s_fields['component']}] {msg}"

                event: dict[str, Any] = {
                    "timestamp": ts,
                    "timestamp_desc": "K8s Log",
                    "message": display,
                    "artifact_type": "k8s_event",
                    "kubernetes": {
                        "level": level,
                        **k8s_fields,
                    },
                }

                if error_val:
                    event["error"] = {"message": error_val}

                yield event

    # ── JSON structured lines ─────────────────────────────────────────────────

    def _parse_json(self, path: Path) -> Generator[dict[str, Any], None, None]:
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open k3s log: {exc}") from exc

        fallback_ts = _mtime_or_now(path)

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

                ts_raw = (
                    obj.get("time")
                    or obj.get("ts")
                    or obj.get("timestamp")
                    or obj.get("@timestamp")
                    or ""
                )
                ts = _normalise_ts(str(ts_raw)) if ts_raw else fallback_ts
                level = str(obj.get("level", obj.get("severity", "info"))).lower()
                msg = str(obj.get("msg", obj.get("message", "")))

                k8s_fields: dict[str, str] = {}
                for src_key, dst_key in _FIELD_MAP.items():
                    val = obj.get(src_key)
                    if val:
                        k8s_fields[dst_key] = str(val)

                display = msg
                if k8s_fields.get("namespace") and k8s_fields.get("pod"):
                    display = f"[{k8s_fields['namespace']}/{k8s_fields['pod']}] {msg}"
                elif k8s_fields.get("component"):
                    display = f"[{k8s_fields['component']}] {msg}"

                error_val = obj.get("error", obj.get("err", ""))

                event: dict[str, Any] = {
                    "timestamp": ts,
                    "timestamp_desc": "K8s Log",
                    "message": display,
                    "artifact_type": "k8s_event",
                    "kubernetes": {
                        "level": level,
                        **k8s_fields,
                    },
                    "raw": obj,
                }

                if error_val:
                    event["error"] = {"message": str(error_val)}

                yield event

    # ── klog v1/v2 text format ────────────────────────────────────────────────

    def _parse_klog(self, path: Path) -> Generator[dict[str, Any], None, None]:
        """
        klog v1/v2:
          E0410 02:56:03.190991  528708 pod_workers.go:1324] "msg" key="val" …

        Date is MMDD without year — infer year from file mtime.
        Structured body (klog v2) is parsed for pod/namespace/container/err fields.
        """
        try:
            fh = open(path, errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open klog file: {exc}") from exc

        try:
            mtime_year = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).year
        except OSError:
            mtime_year = datetime.now(UTC).year

        with fh:
            for raw in fh:
                line = raw.rstrip("\n")
                m = _KLOG_RE.match(line)
                if not m:
                    continue

                level_char, mmdd, time_str, pid, src_file, src_line, body = m.groups()
                level = _KLOG_LEVELS.get(level_char, "info")

                # Build ISO timestamp (MMDD + mtime year, truncate microseconds)
                month = mmdd[:2]
                day = mmdd[2:]
                time_part = time_str.split(".")[0]
                ts = f"{mtime_year}-{month}-{day}T{time_part}Z"

                # Parse structured body
                msg, raw_kv = _parse_klog_body(body)

                # ── Map raw keys → canonical kubernetes fields ────────────────
                k8s: dict[str, Any] = {"level": level, "src_file": src_file, "src_line": src_line}
                error_val = ""

                for key, val in raw_kv.items():
                    low = key.lower()
                    if low in ("pod", "podname", "pod_name"):
                        ns, pod_name = _split_pod_ref(val)
                        k8s["pod"] = pod_name
                        if ns:
                            k8s.setdefault("namespace", ns)
                    elif low in ("namespace", "ns"):
                        k8s["namespace"] = val
                    elif low in ("node", "nodename", "node_name"):
                        k8s["node"] = val
                    elif low in ("container", "containername", "containerid"):
                        k8s["container"] = val
                    elif low in ("image", "imagename"):
                        k8s["image"] = val
                    elif low in ("component", "comp"):
                        k8s["component"] = val
                    elif low in ("reason",):
                        k8s["reason"] = val
                    elif low in ("err", "error"):
                        error_val = val
                    elif low in ("name", "objectname"):
                        k8s["object_name"] = val
                    elif low in ("kind",):
                        k8s["object_kind"] = val

                # ── Build human-readable display ──────────────────────────────
                level_prefix = {"error": "✖ ", "warning": "⚠ ", "fatal": "☠ "}.get(level, "")
                display = f"{level_prefix}{msg}"
                if k8s.get("namespace") and k8s.get("pod"):
                    display = f"{level_prefix}[{k8s['namespace']}/{k8s['pod']}] {msg}"
                elif k8s.get("pod"):
                    display = f"{level_prefix}[{k8s['pod']}] {msg}"
                elif k8s.get("node"):
                    display = f"{level_prefix}[node:{k8s['node']}] {msg}"
                elif k8s.get("component"):
                    display = f"{level_prefix}[{k8s['component']}] {msg}"

                if error_val:
                    # Truncate long error strings for the display message
                    short_err = error_val[:120] + ("…" if len(error_val) > 120 else "")
                    display += f" — {short_err}"

                event: dict[str, Any] = {
                    "timestamp": ts,
                    "timestamp_desc": "K8s Log",
                    "message": display,
                    "artifact_type": "k8s_event",
                    "kubernetes": k8s,
                    "process": {"pid": int(pid)},
                }

                if error_val:
                    event["error"] = {"message": error_val}

                yield event

    def get_stats(self) -> dict[str, Any]:
        return {}
