"""URLhaus (abuse.ch) source — URL / domain / hash reputation.

Real API shape: POST to ``/v1/url/`` (form field ``url``), ``/v1/host/``
(field ``host``) or ``/v1/payload/`` (field ``<hash_type>_hash``). A
``query_status`` of ``ok`` means the IOC is known-bad.
See https://urlhaus-api.abuse.ch/ .
"""

from __future__ import annotations

from ..models import IOC, IOCType, SourceVerdict
from .base import Source, SourceError

_API = "https://urlhaus-api.abuse.ch/v1"


class URLhausSource(Source):
    name = "urlhaus"
    supported_types = (IOCType.URL, IOCType.DOMAIN, IOCType.HASH)
    weight = 1.2  # abuse.ch is high-signal: a hit is almost certainly malicious

    def enrich(self, ioc: IOC) -> SourceVerdict:
        try:
            if ioc.type is IOCType.URL:
                data = self._http_post(f"{_API}/url/", data={"url": ioc.value})
            elif ioc.type is IOCType.DOMAIN:
                data = self._http_post(f"{_API}/host/", data={"host": ioc.value})
            else:  # HASH
                field = "sha256_hash" if len(ioc.value) == 64 else "md5_hash"
                data = self._http_post(f"{_API}/payload/", data={field: ioc.value})
        except SourceError as exc:
            return SourceVerdict(source=self.name, malicious=0.0, confidence=0.0, error=str(exc))

        return self._verdict_from(data)

    def _verdict_from(self, data: dict) -> SourceVerdict:
        status = (data.get("query_status") or "").lower()
        if status == "no_results":
            # Known data set, IOC absent → mild benign signal, low confidence.
            return SourceVerdict(source=self.name, malicious=0.0, confidence=0.3, raw=data)
        if status != "ok":
            return SourceVerdict(
                source=self.name,
                malicious=0.0,
                confidence=0.0,
                error=f"query_status={status or 'unknown'}",
                raw=data,
            )

        labels: list[str] = []
        threat = data.get("threat") or data.get("url_status")
        if threat:
            labels.append(str(threat))
        for tag in data.get("tags") or []:
            labels.append(str(tag))

        # An "ok" hit on abuse.ch means the IOC is listed as a threat.
        online = (data.get("url_status") or "").lower() == "online"
        return SourceVerdict(
            source=self.name,
            malicious=0.95 if online else 0.85,
            confidence=0.95,
            labels=labels,
            raw=data,
        )
