"""AbuseIPDB source — IP reputation.

Real API shape: GET ``/api/v2/check?ipAddress=<ip>`` with a ``Key`` header.
Response ``data.abuseConfidenceScore`` is 0–100. See
https://docs.abuseipdb.com/ .
"""

from __future__ import annotations

from ..models import IOC, IOCType, SourceVerdict
from .base import Source, SourceError

_API = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBSource(Source):
    name = "abuseipdb"
    supported_types = (IOCType.IP,)
    weight = 1.0

    def enrich(self, ioc: IOC) -> SourceVerdict:
        if not self.api_key:
            return SourceVerdict(
                source=self.name,
                malicious=0.0,
                confidence=0.0,
                error="missing api_key",
            )
        try:
            data = self._http_get(
                _API,
                params={"ipAddress": ioc.value, "maxAgeInDays": 90},
                headers={"Key": self.api_key, "Accept": "application/json"},
            )
        except SourceError as exc:
            return SourceVerdict(source=self.name, malicious=0.0, confidence=0.0, error=str(exc))

        d = data.get("data", {})
        score = float(d.get("abuseConfidenceScore", 0)) / 100.0
        total = int(d.get("totalReports", 0))
        # Confidence grows with the number of independent reports (cap at ~20).
        confidence = min(1.0, 0.4 + total / 20.0) if total else 0.4

        labels: list[str] = []
        usage = d.get("usageType")
        if usage:
            labels.append(str(usage))
        if d.get("isTor"):
            labels.append("tor-exit-node")
        country = d.get("countryCode")
        if country:
            labels.append(f"country:{country}")

        return SourceVerdict(
            source=self.name,
            malicious=score,
            confidence=confidence,
            labels=labels,
            raw=d,
        )
