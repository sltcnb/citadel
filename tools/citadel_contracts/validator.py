"""Runtime ForensicEvent validation — the enforcement the contract needs.

Contracts that aren't enforced are just documentation. This validates an event
against the ForensicEvent contract at the points it crosses a boundary (after a
Babel parse, before the Sluice bus emit, after a Rosetta normalize).

Dependency-free by default: the load-bearing rules (required ``timestamp`` in
ISO-8601 ``Z`` form + ``message``; ``raw`` required for structured artifact
types) are checked in plain Python so the standalone package needs nothing. If
``jsonschema`` is installed and a schema path is given, the full JSON Schema is
also enforced (with a FormatChecker, so ``date-time`` is actually checked).
"""

from __future__ import annotations

import re
from typing import Any

from .parser import STRUCTURED_ARTIFACTS

_ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


def validate_forensic_event(
    event: Any, *, schema_path: str | None = None, require_z: bool = True
) -> tuple[bool, str | None]:
    """Return ``(ok, error)``. ``error`` is None when the event is valid."""
    if not isinstance(event, dict):
        return False, f"event is {type(event).__name__}, not an object"
    ts = event.get("timestamp")
    if not isinstance(ts, str) or not ts:
        return False, "missing required 'timestamp'"
    if require_z and not _ISO_Z.match(ts):
        return False, f"'timestamp' not ISO-8601 Z: {ts!r}"
    msg = event.get("message")
    if not isinstance(msg, str) or not msg:
        return False, "missing required 'message'"
    at = event.get("artifact_type")
    if at in STRUCTURED_ARTIFACTS and not isinstance(event.get("raw"), (dict, str)):
        return False, f"structured artifact_type '{at}' requires a 'raw' record"

    if schema_path:
        try:
            import json

            import jsonschema  # type: ignore

            schema = json.loads(open(schema_path, encoding="utf-8").read())
            jsonschema.Draft202012Validator(
                schema, format_checker=jsonschema.FormatChecker()
            ).validate(event)
        except ImportError:
            pass  # jsonschema not installed → core rules already enforced above
        except Exception as exc:  # jsonschema.ValidationError or bad schema path
            return False, f"schema validation failed: {getattr(exc, 'message', exc)}"
    return True, None


def is_valid_forensic_event(event: Any, **kw: Any) -> bool:
    return validate_forensic_event(event, **kw)[0]
