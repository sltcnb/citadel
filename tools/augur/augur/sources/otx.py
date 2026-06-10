"""AlienVault OTX source — multi-type reputation via pulse membership.

Real API shape: GET ``/api/v1/indicators/{section}/{indicator}/general`` with
an ``X-OTX-API-KEY`` header. ``pulse_info.count`` is the number of threat
pulses referencing the indicator. See https://otx.alienvault.com/api .
"""

from __future__ import annotations

from ..models import IOC, IOCType, SourceVerdict
from .base import Source, SourceError

_API = "https://otx.alienvault.com/api/v1/indicators"

_SECTION = {
    IOCType.IP: "IPv4",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.HASH: "file",
}


class OTXSource(Source):
    name = "otx"
    supported_types = (IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH)
    weight = 0.9  # community pulses are broad but noisier than abuse.ch

    def enrich(self, ioc: IOC) -> SourceVerdict:
        if not self.api_key:
            return SourceVerdict(
                source=self.name,
                malicious=0.0,
                confidence=0.0,
                error="missing api_key",
            )
        section = _SECTION[ioc.type]
        try:
            data = self._http_get(
                f"{_API}/{section}/{ioc.value}/general",
                headers={"X-OTX-API-KEY": self.api_key},
            )
        except SourceError as exc:
            return SourceVerdict(source=self.name, malicious=0.0, confidence=0.0, error=str(exc))

        pulse_info = data.get("pulse_info", {}) or {}
        count = int(pulse_info.get("count", 0))
        # Map pulse count → maliciousness with diminishing returns.
        malicious = min(1.0, count / 6.0) if count else 0.0
        confidence = min(1.0, 0.5 + count / 10.0) if count else 0.5

        labels: list[str] = []
        for pulse in (pulse_info.get("pulses") or [])[:5]:
            for tag in pulse.get("tags") or []:
                if tag not in labels:
                    labels.append(str(tag))

        return SourceVerdict(
            source=self.name,
            malicious=malicious,
            confidence=confidence,
            labels=labels,
            raw={"pulse_count": count},
        )
