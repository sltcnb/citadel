"""citadel_contracts.finding — the ONE shape every analysis output takes.

Citadel grew several analysis surfaces (IOC extraction, anomaly scan, MITRE
coverage, kill-chain, entity graph, process tree, modules, co-pilot) and each
parked its output in a different place — some only in frontend React state,
some as Elasticsearch events, some in Redis. The result: an analyst could not
query, export, report on, or re-ingest them the same way.

A **Finding** is the standard, durable record of any such output. It is shaped
as a normal forensic event so that the moment it is written to
``fo-case-{case_id}-finding`` it is — for free — searchable in the timeline,
included by the CSV / ``.citadel`` archive export, eligible for the report, and
re-ingestable like any other event. The anomaly scanner already proved this
pattern by indexing ``artifact_type:anomaly`` events; ``Finding`` generalises it
to every feature.

No third-party dependencies; safe to vendor into any tool image.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# Severity vocabulary — identical to Anvil's ``module.LEVELS`` and the Timeline
# UI, so a module Finding and an IOC finding sort/filter on one scale.
SEVERITIES = ("critical", "high", "medium", "low", "informational")
_SEVERITY_INT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}

# The analysis surfaces that emit findings. Open set — a string not listed here
# is still accepted; this tuple documents the known producers and drives UI
# grouping / filtering.
KINDS = (
    "ioc",        # extracted indicator (ip / domain / hash / url / ...)
    "anomaly",    # statistical spike (z-score)
    "mitre",      # ATT&CK technique coverage
    "killchain",  # reconstructed attack chain step
    "entity",     # entity-graph node/edge of interest
    "proctree",   # process-tree observation
    "module",     # Anvil module finding (capa / yara / pe / ...)
    "copilot",    # AI co-pilot observation
    "baseline",   # rare / outlier baseline value
    "manual",     # analyst-authored, or a promoted/pinned event
)

ARTIFACT_TYPE = "finding"

# ISO8601 UTC, second precision, trailing Z — matches parser.iso_z so finding
# timestamps sort against parsed events without format surprises.
def _iso(dt: datetime | None = None) -> str:
    dt = dt or datetime.now(UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stable_id(kind: str, source_feature: str, title: str, dedup_key: str | None) -> str:
    """Deterministic finding_id so re-running a feature overwrites rather than
    duplicates. Caller passes ``dedup_key`` (e.g. the IOC value, the technique
    id, the host+event_id) when a natural key exists; otherwise a random id."""
    if dedup_key is None:
        return uuid.uuid4().hex
    h = hashlib.sha1(f"{kind}\x00{source_feature}\x00{dedup_key}".encode()).hexdigest()
    return h[:32]


@dataclass
class Finding:
    """A single standardized analysis output.

    Required: ``kind``, ``title``. Everything else is optional but the entity
    sub-objects (``host`` / ``user`` / ``process`` / ``network``) and
    ``evidence`` (source ``fo_id`` list) are what let a finding link back to the
    raw timeline events it was derived from.
    """

    kind: str
    title: str
    severity: str = "informational"
    description: str = ""
    source_feature: str = ""           # which panel/module produced it
    timestamp: str | None = None       # event/analysis time (ISO8601 Z)
    timestamp_desc: str = "Finding"
    host: dict[str, Any] = field(default_factory=dict)
    user: dict[str, Any] = field(default_factory=dict)
    process: dict[str, Any] = field(default_factory=dict)
    network: dict[str, Any] = field(default_factory=dict)
    techniques: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)   # source fo_id(s)
    tags: list[str] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)   # kind-specific blob
    provenance: dict[str, Any] = field(default_factory=dict)  # run_id/query/params/version
    dedup_key: str | None = None       # natural key for idempotent re-runs

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            self.severity = "informational"

    @property
    def severity_int(self) -> int:
        return _SEVERITY_INT[self.severity]

    def to_event(self, case_id: str, ingested_at: str | None = None) -> dict[str, Any]:
        """Serialise to an ES event document for ``fo-case-{case_id}-finding``.

        The shape is a superset of the standard forensic event so the existing
        search / export / report / re-ingest paths consume it unchanged.
        """
        ts = self.timestamp or _iso()
        fo_id = _stable_id(self.kind, self.source_feature, self.title, self.dedup_key)
        now = ingested_at or _iso()
        doc: dict[str, Any] = {
            "fo_id": fo_id,
            "finding_id": fo_id,
            "case_id": case_id,
            "artifact_type": ARTIFACT_TYPE,
            "kind": self.kind,
            "source_feature": self.source_feature or self.kind,
            "severity": self.severity,
            "severity_int": self.severity_int,
            "timestamp": ts,
            "timestamp_desc": self.timestamp_desc,
            "ingested_at": now,
            "message": self.title,
            "description": self.description,
            "tags": list(dict.fromkeys([*self.tags, "finding", self.kind])),
            "evidence": list(self.evidence),
            "is_flagged": False,
            "is_pinned": False,
            "finding": {
                "kind": self.kind,
                "title": self.title,
                "severity": self.severity,
                "source_feature": self.source_feature,
                "payload": self.payload,
                "provenance": self.provenance,
            },
            "raw": {"finding": self.payload},
        }
        if self.host:
            doc["host"] = self.host
        if self.user:
            doc["user"] = self.user
        if self.process:
            doc["process"] = self.process
        if self.network:
            doc["network"] = self.network
        if self.techniques:
            doc["techniques"] = list(self.techniques)
            doc["mitre"] = {"id": self.techniques}
        return doc


def make_finding(kind: str, title: str, **kwargs: Any) -> Finding:
    """Convenience constructor mirroring ``Result.add_finding`` ergonomics."""
    return Finding(kind=kind, title=title, **kwargs)
