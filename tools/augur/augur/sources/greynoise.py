"""GreyNoise source — internet-background-noise classification for IPs.

Real API shape (community endpoint): GET
``https://api.greynoise.io/v3/community/{ip}`` with a ``key`` header; response
carries ``classification`` (malicious|benign|unknown) and ``noise`` (bool).
See https://docs.greynoise.io .
"""

from __future__ import annotations

from ..models import IOC, IOCType, SourceVerdict
from .base import Source, SourceError

_API = "https://api.greynoise.io/v3/community"
_SCORE = {"malicious": 0.9, "benign": 0.0, "unknown": 0.3}


class GreyNoiseSource(Source):
    name = "greynoise"
    supported_types = (IOCType.IP,)
    weight = 0.8

    def enrich(self, ioc: IOC) -> SourceVerdict:
        if not self.api_key:
            return SourceVerdict(
                source=self.name, malicious=0.0, confidence=0.0, error="missing api_key"
            )
        try:
            data = self._http_get(f"{_API}/{ioc.value}", headers={"key": self.api_key})
        except SourceError as exc:
            return SourceVerdict(source=self.name, malicious=0.0, confidence=0.0, error=str(exc))

        classification = str(data.get("classification", "unknown")).lower()
        malicious = _SCORE.get(classification, 0.3)
        confidence = 0.8 if classification in ("malicious", "benign") else 0.4
        labels = [f"greynoise:{classification}"]
        if data.get("noise"):
            labels.append("internet-noise")
        if data.get("name"):
            labels.append(str(data["name"]))
        return SourceVerdict(
            source=self.name,
            malicious=malicious,
            confidence=confidence,
            labels=labels,
            raw={"classification": classification, "noise": bool(data.get("noise"))},
        )
