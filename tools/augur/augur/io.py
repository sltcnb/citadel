"""Input parsing for IOC files.

Accepts several shapes so it slots into the Citadel pipeline easily:

* a JSON list of strings           → ``["1.2.3.4", "evil.com"]``
* a JSON list of objects           → ``[{"value": "1.2.3.4", "type": "ip"}]``
* a wrapped object                 → ``{"iocs": [...]}``
* a list of ForensicEvent-like dicts carrying an IOC in ``raw``/``message``
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import IOC


def _coerce(entry: Any) -> IOC | None:
    if isinstance(entry, str):
        return IOC.parse(entry) if entry.strip() else None
    if isinstance(entry, dict):
        value = entry.get("value") or entry.get("ioc") or entry.get("indicator")
        if not value:
            return None
        return IOC.parse(str(value), type_hint=entry.get("type"))
    return None


def load_iocs(path: str | Path) -> list[IOC]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("iocs") or data.get("indicators") or []
    if not isinstance(data, list):
        raise ValueError("IOC input must be a JSON list or an object with an 'iocs' list")

    iocs: list[IOC] = []
    seen: set[tuple[str, str]] = set()
    for entry in data:
        ioc = _coerce(entry)
        if ioc is None:
            continue
        key = (ioc.type.value, ioc.normalized)
        if key in seen:
            continue
        seen.add(key)
        iocs.append(ioc)
    return iocs
