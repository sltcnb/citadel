"""Core data models for Augur.

These mirror the IOC taxonomy used by the Citadel CTI router
(``api/routers/cti.py``): hash, ip, domain, url, email, filename.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class IOCType(str, Enum):
    """Supported indicator types (aligned with the Citadel CTI taxonomy)."""

    HASH = "hash"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILENAME = "filename"


_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def infer_ioc_type(value: str) -> IOCType:
    """Best-effort classification of a raw indicator string."""
    v = value.strip()
    if v.lower().startswith(("http://", "https://", "ftp://")):
        return IOCType.URL
    if _EMAIL_RE.match(v):
        return IOCType.EMAIL
    try:
        ipaddress.ip_address(v)
        return IOCType.IP
    except ValueError:
        pass
    if _HASH_RE.match(v):
        return IOCType.HASH
    if _DOMAIN_RE.match(v):
        return IOCType.DOMAIN
    return IOCType.FILENAME


@dataclass
class IOC:
    """An indicator of compromise to enrich."""

    value: str
    type: IOCType

    @classmethod
    def parse(cls, value: str, type_hint: str | None = None) -> IOC:
        if type_hint:
            return cls(value=value.strip(), type=IOCType(type_hint))
        return cls(value=value.strip(), type=infer_ioc_type(value))

    @property
    def normalized(self) -> str:
        """Lower-cased value for case-insensitive types (matches CTI store)."""
        return self.value if self.type is IOCType.URL else self.value.lower()


@dataclass
class SourceVerdict:
    """One source's opinion about one IOC.

    ``malicious`` is a 0.0–1.0 maliciousness probability; ``confidence`` is
    how much the source trusts its own verdict (data coverage / freshness).
    """

    source: str
    malicious: float
    confidence: float = 1.0
    labels: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def __post_init__(self) -> None:
        self.malicious = _clamp(self.malicious)
        self.confidence = _clamp(self.confidence)


@dataclass
class EnrichedIOC:
    """An IOC after enrichment across all sources, with a fused score."""

    ioc: IOC
    verdicts: list[SourceVerdict] = field(default_factory=list)
    score: float = 0.0
    severity: str = "unknown"
    labels: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.ioc.value,
            "type": self.ioc.type.value,
            "score": round(self.score, 4),
            "severity": self.severity,
            "labels": self.labels,
            "verdicts": [
                {
                    "source": v.source,
                    "malicious": round(v.malicious, 4),
                    "confidence": round(v.confidence, 4),
                    "labels": v.labels,
                    "error": v.error,
                }
                for v in self.verdicts
            ],
        }


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(x)))
