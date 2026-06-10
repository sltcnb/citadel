"""STIX 2.1 bundle export.

Emits a ``bundle`` containing one ``indicator`` SDO per enriched IOC, plus a
single ``identity`` SDO for Augur as the producer. Patterns follow the STIX 2.1
comparison-expression grammar used by the Citadel CTI router
(``api/routers/cti.py`` ``_STIX_PATTERNS``), so exports round-trip back into it.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from .models import IOC, EnrichedIOC, IOCType

SPEC_VERSION = "2.1"

# Deterministic namespace so the same IOC always maps to the same STIX id
# (idempotent re-export / dedup downstream).
_NS = uuid.UUID("6f3e1d2c-0a4b-4c5d-8e9f-0123456789ab")

_PRODUCER_ID = "identity--" + str(uuid.uuid5(_NS, "augur-producer"))


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _hash_algo(value: str) -> str:
    return {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(value), "SHA-256")


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def ioc_to_pattern(ioc: IOC) -> str:
    """Render a STIX 2.1 comparison-expression pattern for an IOC."""
    v = _escape(ioc.value)
    if ioc.type is IOCType.IP:
        kind = "ipv6-addr" if ":" in ioc.value else "ipv4-addr"
        return f"[{kind}:value = '{v}']"
    if ioc.type is IOCType.DOMAIN:
        return f"[domain-name:value = '{v}']"
    if ioc.type is IOCType.URL:
        return f"[url:value = '{v}']"
    if ioc.type is IOCType.EMAIL:
        return f"[email-addr:value = '{v}']"
    if ioc.type is IOCType.FILENAME:
        return f"[file:name = '{v}']"
    # HASH
    return f"[file:hashes.'{_hash_algo(ioc.value)}' = '{v}']"


def _indicator_id(ioc: IOC) -> str:
    seed = f"{ioc.type.value}:{ioc.normalized}"
    return "indicator--" + str(uuid.uuid5(_NS, seed))


def enriched_to_indicator(enriched: EnrichedIOC) -> dict[str, Any]:
    """Convert one EnrichedIOC into a STIX 2.1 indicator SDO."""
    now = _now()
    labels = ["malicious-activity"] if enriched.score >= 0.5 else ["benign"]

    confidence = int(round(enriched.score * 100))  # STIX confidence is 0–100
    sources = [v.source for v in enriched.verdicts if v.error is None]

    sdo: dict[str, Any] = {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": _indicator_id(enriched.ioc),
        "created_by_ref": _PRODUCER_ID,
        "created": now,
        "modified": now,
        "name": f"{enriched.ioc.type.value}: {enriched.ioc.value}",
        "pattern": ioc_to_pattern(enriched.ioc),
        "pattern_type": "stix",
        "pattern_version": SPEC_VERSION,
        "valid_from": now,
        "indicator_types": labels,
        "confidence": confidence,
        # Augur-specific provenance under x_ extension keys (STIX-legal).
        "x_augur_score": round(enriched.score, 4),
        "x_augur_severity": enriched.severity,
        "x_augur_sources": sources,
        "labels": labels + enriched.labels,
    }
    return sdo


def _producer_identity() -> dict[str, Any]:
    now = _now()
    return {
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": _PRODUCER_ID,
        "created": now,
        "modified": now,
        "name": "Augur",
        "identity_class": "system",
        "description": "Citadel Augur intel enrichment",
    }


def build_bundle(enriched: list[EnrichedIOC]) -> dict[str, Any]:
    """Build a complete STIX 2.1 bundle from enriched IOCs."""
    objects: list[dict[str, Any]] = [_producer_identity()]
    objects.extend(enriched_to_indicator(e) for e in enriched)

    # Bundle id derives from object content for reproducibility.
    digest = hashlib.sha256("".join(o["id"] for o in objects).encode("utf-8")).hexdigest()
    bundle_id = "bundle--" + str(uuid.uuid5(_NS, digest))

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }
