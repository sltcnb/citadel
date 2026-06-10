"""MISP interop — export enriched IOCs to a MISP Event, and parse one back.

MISP's wire format is ``{"Event": {"info", "date", "Attribute": [...], "Tag": [...]}}``.
``build_event`` renders enriched IOCs as MISP attributes (typed + tagged with
the fused labels/severity); ``parse_event`` reads a MISP Event back into
``(value, type, labels)`` tuples. The two round-trip, so a bundle exported from
Augur re-imports into the platform's CTI store without loss of the indicator set.
"""

from __future__ import annotations

from typing import Any

from .models import IOC, EnrichedIOC, IOCType

# IOCType -> (MISP attribute type, MISP category)
_TYPE_TO_MISP = {
    IOCType.IP: ("ip-dst", "Network activity"),
    IOCType.DOMAIN: ("domain", "Network activity"),
    IOCType.URL: ("url", "Network activity"),
    IOCType.EMAIL: ("email-src", "Payload delivery"),
    IOCType.FILENAME: ("filename", "Payload delivery"),
}
_HASH_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
# reverse map MISP attribute type -> IOCType
_MISP_TO_TYPE = {
    "ip-dst": IOCType.IP,
    "ip-src": IOCType.IP,
    "domain": IOCType.DOMAIN,
    "hostname": IOCType.DOMAIN,
    "url": IOCType.URL,
    "email-src": IOCType.EMAIL,
    "email-dst": IOCType.EMAIL,
    "filename": IOCType.FILENAME,
    "md5": IOCType.HASH,
    "sha1": IOCType.HASH,
    "sha256": IOCType.HASH,
}


def _misp_type(ioc: IOC) -> tuple[str, str]:
    if ioc.type is IOCType.HASH:
        return _HASH_BY_LEN.get(len(ioc.value), "sha256"), "Payload delivery"
    return _TYPE_TO_MISP.get(ioc.type, ("text", "Other"))


def enriched_to_attribute(enriched: EnrichedIOC) -> dict[str, Any]:
    mtype, category = _misp_type(enriched.ioc)
    tags = [{"name": lbl} for lbl in enriched.labels]
    tags.append({"name": f'augur:severity="{enriched.severity}"'})
    return {
        "type": mtype,
        "category": category,
        "value": enriched.ioc.value,
        "to_ids": enriched.score >= 0.5,
        "comment": f"Augur score={round(enriched.score, 3)} severity={enriched.severity}",
        "Tag": tags,
    }


def build_event(
    enriched: list[EnrichedIOC], *, info: str = "Augur enrichment", date: str = "1970-01-01"
) -> dict[str, Any]:
    """Render enriched IOCs as a MISP Event dict."""
    return {
        "Event": {
            "info": info,
            "date": date,
            "analysis": "2",
            "threat_level_id": "2",
            "Attribute": [enriched_to_attribute(e) for e in enriched],
            "Tag": [{"name": "source:augur"}],
        }
    }


def parse_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse a MISP Event back into ``[{value, type, labels}]``."""
    ev = event.get("Event", event)
    out: list[dict[str, Any]] = []
    for attr in ev.get("Attribute", []) or []:
        ioc_type = _MISP_TO_TYPE.get(attr.get("type", ""))
        if ioc_type is None:
            continue
        labels = [t.get("name") for t in attr.get("Tag", []) or [] if t.get("name")]
        out.append({"value": attr.get("value"), "type": ioc_type.value, "labels": labels})
    return out
