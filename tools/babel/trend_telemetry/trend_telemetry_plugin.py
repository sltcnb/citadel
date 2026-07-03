"""
Trend Micro Endpoint Sensor / Vision One telemetry plugin.

Parses exported Trend Micro Apex One "Endpoint Sensor" / Vision One (XDR)
telemetry — the rich EDR event stream (productCode "xes", eventSourceType
TELEMETRY). Each record carries a full process context (process + parent, path,
cmdline, signer, hashes), the endpoint identity (host / IP / MAC / OS / user),
network/download context (request URL, object host, downloaded file), and
Trend/MITRE detection tags.

Accepts a JSON array, NDJSON (one object per line), or a single JSON object.
Each telemetry record becomes one normalized forensic event so it lands in the
timeline with process.*, network/url.*, host.*, user.*, mitre.id and hashes —
feeding the process tree, IOC panel, entity graph, MITRE coverage and reports
exactly like a native artifact.
"""

from __future__ import annotations

import json
import re
from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

# MITRE technique id embedded in Trend tag strings, e.g. "MITRE.T1566 - Phishing".
_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# Trend fingerprint keys — any of these present ⇒ this is Trend telemetry.
_TREND_MARKERS = ("eventSourceType", "eventSubId", "endpointGuid", "processHashId", "productCode")


def _first(v: Any) -> str:
    """Trend multi-value fields (endpointIp, MAC…) arrive as list or newline str."""
    if isinstance(v, list):
        return str(v[0]) if v else ""
    if isinstance(v, str):
        return v.splitlines()[0].strip() if v else ""
    return str(v) if v is not None else ""


def _all(v: Any) -> list[str]:
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, str):
        return [ln.strip() for ln in v.splitlines() if ln.strip()]
    return [str(v)] if v not in (None, "") else []


def _mitre_ids(tags: Any) -> list[str]:
    ids: list[str] = []
    for t in _all(tags):
        for m in _MITRE_RE.findall(t):
            u = m.upper()
            if u not in ids:
                ids.append(u)
    return ids


class TrendTelemetryPlugin(BasePlugin):
    """Parses Trend Micro Endpoint Sensor / Vision One telemetry JSON."""

    PLUGIN_NAME = "trend_telemetry"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "trend_telemetry"
    SUPPORTED_EXTENSIONS = [".json", ".ndjson", ".jsonl", ".log"]
    SUPPORTED_MIME_TYPES = ["application/json", "text/plain"]
    PLUGIN_PRIORITY = 92  # above generic json/ndjson fallbacks

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return []

    @classmethod
    def can_handle(cls, file_path, mime_type) -> bool:
        try:
            with open(file_path, errors="replace") as fh:
                head = fh.read(4096)
        except OSError:
            return False
        # Cheap fingerprint: Trend telemetry keys in the first chunk.
        return sum(1 for m in _TREND_MARKERS if f'"{m}"' in head) >= 2

    # ── record iteration (array / ndjson / single object) ──────────────────────
    def _records(self) -> Generator[dict, None, None]:
        path = self.ctx.source_file_path
        try:
            text = path.read_text(errors="replace").strip()
        except OSError as exc:
            raise PluginFatalError(f"Cannot read Trend telemetry: {exc}") from exc
        if not text:
            return
        # Whole-file JSON (array or object)?
        if text[0] in "[{":
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    yield from (r for r in data if isinstance(r, dict))
                    return
                if isinstance(data, dict):
                    # Some exports wrap records under a key (data/events/results).
                    for key in ("data", "events", "results", "logs"):
                        if isinstance(data.get(key), list):
                            yield from (r for r in data[key] if isinstance(r, dict))
                            return
                    yield data
                    return
            except json.JSONDecodeError:
                pass  # fall through to NDJSON
        # NDJSON — one object per line.
        for line in text.splitlines():
            line = line.strip()
            if not line or line[0] != "{":
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield obj
            except json.JSONDecodeError:
                continue

    def parse(self) -> Generator[dict[str, Any], None, None]:
        for rec in self._records():
            ev = self._to_event(rec)
            if ev:
                yield ev

    def _to_event(self, r: dict) -> dict[str, Any] | None:
        get = r.get

        # ── timestamp ──────────────────────────────────────────────────────────
        ts_raw = get("firstSeen") or get("eventTime") or get("processLaunchTime") \
            or get("lastSeen") or get("logReceivedTime") or ""
        ts = self._norm_ts(ts_raw)

        # ── process ────────────────────────────────────────────────────────────
        process: dict[str, Any] = {}
        pname_path = get("processName") or get("processFilePath") or ""
        if pname_path:
            process["path"] = pname_path
            process["name"] = pname_path.replace("/", "\\").split("\\")[-1]
        if get("processCmd"):
            process["command_line"] = get("processCmd")
        if get("processPid") is not None:
            try:
                process["pid"] = int(get("processPid"))
            except (ValueError, TypeError):
                pass
        _h = {}
        if get("processFileHashMd5"):
            _h["md5"] = get("processFileHashMd5")
        if get("processFileHashSha1"):
            _h["sha1"] = get("processFileHashSha1")
        if get("processFileHashSha256"):
            _h["sha256"] = get("processFileHashSha256")
        if _h:
            process["hash"] = _h
        if get("processSigner"):
            process["signer"] = get("processSigner")
        # parent
        parent_path = get("parentName") or get("parentFilePath") or ""
        if parent_path:
            process["parent_name"] = parent_path.replace("/", "\\").split("\\")[-1]
            process["parent_path"] = parent_path
        if get("parentCmd"):
            process["parent_command_line"] = get("parentCmd")
        if get("parentPid") is not None:
            try:
                process["parent_pid"] = int(get("parentPid"))
            except (ValueError, TypeError):
                pass

        # ── host / user ──────────────────────────────────────────────────────
        host: dict[str, Any] = {}
        if get("endpointHostName"):
            host["hostname"] = get("endpointHostName")
        ips = _all(get("endpointIp"))
        if ips:
            host["ip"] = ips[0]
            if len(ips) > 1:
                host["ips"] = ips
        macs = _all(get("endpointMacAddress"))
        if macs:
            host["mac"] = macs[0]
        if get("osName") or get("osVer"):
            host["os"] = f"{get('osName', '')} {get('osVer', '')}".strip()

        user: dict[str, Any] = {}
        uname = get("logonUser") or get("processUser") or ""
        if uname:
            user["name"] = uname
        if get("userDomain") or get("processUserDomain"):
            user["domain"] = get("userDomain") or get("processUserDomain")

        # ── network / download ────────────────────────────────────────────────
        url_obj: dict[str, Any] = {}
        req = get("request") or ""
        if req:
            url_obj["full"] = req
        obj_host = get("objectHostName") or ""
        if obj_host:
            url_obj["domain"] = obj_host

        file_obj: dict[str, Any] = {}
        if get("objectFilePath"):
            ofp = get("objectFilePath")
            file_obj["path"] = ofp
            file_obj["name"] = ofp.replace("/", "\\").split("\\")[-1]

        # ── detection tags / MITRE ─────────────────────────────────────────────
        tag_list = _all(get("tags"))
        mitre_ids = _mitre_ids(get("tags"))
        severity = (get("filterRiskLevel") or "").lower() or None

        # ── message ─────────────────────────────────────────────────────────────
        sub = get("eventSubId") or get("eventId") or ""
        bits = [str(sub)] if sub else []
        if uname:
            bits.append(uname)
        if process.get("name"):
            bits.append(process["name"])
        if req:
            bits.append(f"→ {req}")
        elif file_obj.get("name"):
            bits.append(f"→ {file_obj['name']}")
        msg = "  ".join(bits) or "Trend telemetry event"
        if tag_list:
            msg += "  [" + "; ".join(tag_list[:3]) + "]"

        event: dict[str, Any] = {
            "timestamp": ts,
            "timestamp_desc": "Trend EDR Telemetry",
            "message": msg,
            "artifact_type": "trend_telemetry",
            "os": "windows" if (get("osName") == "Windows") else (get("osName") or "").lower(),
            "raw": {"content": json.dumps(r, ensure_ascii=False)[:20000]},
        }
        if process:
            event["process"] = process
        if host:
            event["host"] = host
        if user:
            event["user"] = user
        if url_obj:
            event["url"] = url_obj
        if file_obj:
            event["file"] = file_obj
        if mitre_ids:
            event["mitre"] = {"id": mitre_ids}
        # Preserve Trend-native tags plus derived MITRE ids as searchable tags.
        tags = list(tag_list)
        tags += [m for m in mitre_ids if m not in tags]
        if tags:
            event["tags"] = tags
        if severity:
            event["level"] = severity
        return event

    @staticmethod
    def _norm_ts(raw: str) -> str:
        raw = str(raw or "").strip()
        if not raw:
            return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Trend uses ISO8601 Z already (2026-07-01T11:51:07Z) — pass through if valid.
        try:
            s = raw.replace("Z", "+00:00")
            datetime.fromisoformat(s)
            return raw if raw.endswith("Z") else s
        except ValueError:
            return raw  # keep whatever it is; downstream is tolerant

    def get_stats(self) -> dict[str, Any]:
        return {}
