"""IOC normalisation for conclusions.

Indicators are copied by the model from the alert text and from evidence. Two
things go wrong on the way, and both must be caught before an IOC is promoted
to a watchlist or a report:

- defanged forms (``evil[.]com``, ``hxxp://``) that match nothing downstream;
- corrupted Windows paths, typically from an upstream tool that decoded the
  backslashes of ``C:\\Windows\\testFile`` as escape sequences: ``\\t`` became a
  TAB (or a space) and the remaining separators vanished, giving
  ``C:Windows<TAB>estFile``. A corrupted path is withheld with a warning, never
  emitted — it would match nothing and look like a real indicator.
"""

from __future__ import annotations

import re

_CONTROL = re.compile(r"[\t\n\r\x00-\x08\x0b\x0c\x0e-\x1f]")
# A drive letter not followed by a separator: "C:Windows", "D:Users".
_DRIVE_NO_SEP = re.compile(r"^[A-Za-z]:[A-Za-z]")
_ESCAPES = {"\t": "\\t", "\n": "\\n", "\r": "\\r"}


def refang(value: str) -> str:
    v = value.strip()
    v = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", v)
    v = re.sub(r"(?i)^hxxp", "http", v)
    v = v.replace("[:]", ":").replace("[@]", "@")
    return v


def path_problem(value: str) -> str | None:
    """Why *value* looks like a damaged Windows path, or None."""
    if _CONTROL.search(value):
        return "contains a control character (an unescaped \\t / \\n upstream)"
    if _DRIVE_NO_SEP.match(value):
        return "drive letter without a separator (backslashes lost upstream)"
    return None


def suggest_repair(value: str) -> str:
    """Best-effort reconstruction for the analyst to verify — never emitted as an IOC."""
    v = "".join(_ESCAPES.get(c, c) for c in value)
    if _DRIVE_NO_SEP.match(v):
        v = v[:2] + "\\" + v[2:]
    return v


def normalize_iocs(values: list) -> tuple[list[str], list[dict]]:
    """Clean, deduplicated IOCs plus warnings for the ones withheld."""
    out: list[str] = []
    seen: set[str] = set()
    warnings: list[dict] = []
    for raw in values or []:
        if not isinstance(raw, str) or not raw.strip():
            continue
        v = refang(raw)
        problem = path_problem(v)
        if problem:
            warnings.append({"value": raw, "problem": problem, "possible_original": suggest_repair(v)})
            continue
        key = v.lower()
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out, warnings
