"""Core ForensicEvent -> ECS v8 normalization logic.

Pure, dependency-light (PyYAML only). The artifact_type -> ECS mapping is
driven entirely by a field-map yaml so analysts can extend coverage without
touching code. See fieldmaps/default.yaml.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .enrich import enrich_event

_DEFAULT_MAP = Path(__file__).parent / "fieldmaps" / "default.yaml"

# Standard ECS enrichment sub-objects a ForensicEvent may already carry; Rosetta
# passes these through verbatim (parsers emit them in ECS-ish shape).
_PASSTHROUGH_OBJECTS = (
    "host",
    "user",
    "process",
    "network",
    "http",
    "file",
    "dns",
    "url",
    "source",
    "destination",
    "registry",
    "email",
    "container",
    "cloud",
    "tls",
    "client",
    "server",
)

_OFFSET_RE = re.compile(r"([+-]\d{2}):?(\d{2})$")


def to_iso_z(value: Any) -> str | None:
    """Canonicalize any timestamp to ISO-8601 UTC with a ``Z`` suffix.

    Accepts ISO strings (with ``Z``, ``+00:00``, or other offsets), epoch
    seconds (int/float), or ``datetime``. The whole project standardises on the
    ``...Z`` form here, at the canonicalization boundary, so ECS ``@timestamp``
    is always uniform regardless of how an upstream parser formatted it.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    s = str(value).strip()
    if s.endswith(("Z", "z")):
        return s[:-1] + "Z"
    # normalise an explicit offset to UTC Z
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        # last resort: strip a trailing +00:00 so we never emit a non-Z offset
        return _OFFSET_RE.sub("Z", s)


def load_fieldmap(path: str | Path | None = None) -> dict[str, Any]:
    """Load a field-map yaml. Falls back to the bundled default."""
    p = Path(path) if path else _DEFAULT_MAP
    with open(p, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    data.setdefault("default", {"category": [], "type": [], "fields": {}})
    data.setdefault("artifact_types", {})
    return data


def _get(source: dict[str, Any], dotted: str) -> Any:
    """Resolve a possibly-dotted key against a nested dict. Returns None if absent."""
    cur: Any = source
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _set(target: dict[str, Any], dotted: str, value: Any) -> None:
    """Set a dotted ECS field path, creating intermediate dicts."""
    parts = dotted.split(".")
    cur = target
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


class Normalizer:
    """Maps ForensicEvent dicts to ECS v8 documents using a field-map."""

    def __init__(self, fieldmap: dict[str, Any], ecs_version: str | None = None):
        self.fieldmap = fieldmap
        self.ecs_version = ecs_version or fieldmap.get("ecs_version", "8.11")
        self._types = fieldmap.get("artifact_types", {})
        self._default = fieldmap.get("default", {"category": [], "type": [], "fields": {}})
        self._attack = fieldmap.get("attack", {})

    def normalize(self, event: dict[str, Any]) -> dict[str, Any]:
        """Return an ECS v8 document for one ForensicEvent."""
        artifact_type = event.get("artifact_type")
        spec = self._types.get(artifact_type, self._default)

        raw = event.get("raw")
        raw_obj = raw if isinstance(raw, dict) else {}

        doc: dict[str, Any] = {
            "@timestamp": to_iso_z(event.get("timestamp")),
            "ecs": {"version": self.ecs_version},
            "event": {},
        }

        # event categorization from the map
        category = spec.get("category") or []
        type_ = spec.get("type") or []
        if category:
            doc["event"]["category"] = list(category)
        if type_:
            doc["event"]["type"] = list(type_)

        # event.action from timestamp_desc / parser
        action = event.get("timestamp_desc") or event.get("parser")
        if action:
            doc["event"]["action"] = action

        if event.get("os"):
            _set(doc, "host.os.type", event["os"])

        # message preserved
        if event.get("message") is not None:
            doc["message"] = event["message"]

        # Passthrough of standard ECS enrichment sub-objects. Babel parsers
        # already emit these in ECS-ish shape (host.*, user.*, network.*, …);
        # carry them into the ECS doc instead of dropping them, then let the
        # per-type field-map (below) refine/add on top. Keeps the parser's
        # structured output intact across the canonicalization boundary.
        for key in _PASSTHROUGH_OBJECTS:
            val = event.get(key)
            if isinstance(val, dict) and val:
                merged = dict(doc.get(key) or {})
                merged.update(val)
                doc[key] = merged

        # per-type field copies: ECS dotted target <- raw/event dotted source
        for ecs_field, source_key in (spec.get("fields") or {}).items():
            value = _get(raw_obj, source_key)
            if value is None:
                value = _get(event, source_key)
            if value is not None:
                _set(doc, ecs_field, value)

        # ATT&CK / OSSEM enrichment: explicit tags on the event win; otherwise
        # fall back to the artifact_type -> technique map.
        tech_ids, tactic = self._extract_attack(event, raw_obj, artifact_type)
        if tech_ids:
            _set(doc, "threat.technique.id", tech_ids)
        if tactic:
            _set(doc, "threat.tactic.name", tactic)

        # source_path passthrough -> ECS log.file.path
        if event.get("source_path"):
            _set(doc, "log.file.path", event["source_path"])

        # raw retention under citadel.raw (always, structured or string)
        if raw is not None:
            _set(doc, "citadel.raw", raw)

        # drop an empty event block defensively (shouldn't happen)
        if not doc["event"]:
            doc.pop("event")

        # Network enrichment (GeoIP/ASN/rDNS). Graceful no-op when the geoip2
        # library or .mmdb databases are absent; never raises, so it can't
        # break canonicalization. Operates on the ECS source/destination/
        # client/server.ip fields populated above.
        enrich_event(doc)

        return doc

    _TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

    def _extract_attack(self, event, raw_obj, artifact_type):
        """Return ``(technique_ids, tactic_name)``.

        Prefers explicit ATT&CK signals on the event (``mitre``/``technique``/
        ``attack`` keys, or ``attack.tNNNN`` tags) — OSSEM-style provenance —
        and falls back to the artifact_type default map for untagged events."""
        ids: list[str] = []
        tactic = None
        for src in (event, raw_obj):
            for key in ("mitre", "technique", "attack", "techniques", "tags"):
                val = src.get(key) if isinstance(src, dict) else None
                if not val:
                    continue
                blob = " ".join(val) if isinstance(val, list) else str(val)
                for m in self._TECH_RE.findall(blob.upper()):
                    if m not in ids:
                        ids.append(m)
            for tkey in ("tactic", "mitre_tactic"):
                tactic = tactic or (src.get(tkey) if isinstance(src, dict) else None)
        if not ids and artifact_type in self._attack:
            entry = self._attack[artifact_type]
            ids = [entry["technique"]]
            tactic = tactic or entry.get("tactic")
        return ids, tactic


def normalize_event(
    event: dict[str, Any],
    fieldmap: dict[str, Any] | None = None,
    ecs_version: str | None = None,
) -> dict[str, Any]:
    """Convenience one-shot: normalize a single event with the default map."""
    fm = fieldmap or load_fieldmap()
    return Normalizer(fm, ecs_version=ecs_version).normalize(event)
