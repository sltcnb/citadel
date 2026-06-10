"""Shodan source — host exposure / vuln reputation for IPs.

Real API shape: GET ``https://api.shodan.io/shodan/host/{ip}?key=KEY``; the
response carries ``ports``, ``tags`` and ``vulns``. We map presence of known
vulns / malicious tags to a maliciousness score. See https://developer.shodan.io .
"""

from __future__ import annotations

from ..models import IOC, IOCType, SourceVerdict
from .base import Source, SourceError

_API = "https://api.shodan.io/shodan/host"
_BAD_TAGS = {"malware", "compromised", "honeypot", "scanner", "tor", "proxy"}


class ShodanSource(Source):
    name = "shodan"
    supported_types = (IOCType.IP,)
    weight = 0.7  # exposure signal, not a direct maliciousness verdict

    def enrich(self, ioc: IOC) -> SourceVerdict:
        if not self.api_key:
            return SourceVerdict(
                source=self.name, malicious=0.0, confidence=0.0, error="missing api_key"
            )
        try:
            data = self._http_get(f"{_API}/{ioc.value}", params={"key": self.api_key})
        except SourceError as exc:
            return SourceVerdict(source=self.name, malicious=0.0, confidence=0.0, error=str(exc))

        tags = [str(t) for t in (data.get("tags") or [])]
        vulns = list(data.get("vulns") or [])
        bad = [t for t in tags if t.lower() in _BAD_TAGS]
        malicious = min(1.0, 0.4 * len(bad) + 0.2 * min(len(vulns), 3))
        confidence = 0.6 if (tags or vulns) else 0.4
        labels = bad + [f"CVE:{v}" for v in vulns[:5]]
        return SourceVerdict(
            source=self.name,
            malicious=malicious,
            confidence=confidence,
            labels=labels,
            raw={"ports": data.get("ports", []), "vuln_count": len(vulns)},
        )
