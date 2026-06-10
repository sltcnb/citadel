"""Reusable golden-file harness helpers.

Run a parser over a fixture, scrub non-deterministic fields, and (optionally)
validate every emitted event against the shared ForensicEvent contract.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from babel.base_plugin import PluginContext

from .cases import VOLATILE_KEYS, GoldenCase

# contracts/ lives at the repo root.
# harness.py -> golden/ -> tests/ -> plugins/ -> tools/ -> <repo root>
_REPO_ROOT = Path(__file__).resolve().parents[4]
FORENSIC_EVENT_SCHEMA = _REPO_ROOT / "contracts" / "forensic_event.schema.json"


def scrub_event(event: dict[str, Any]) -> dict[str, Any]:
    """Drop non-deterministic keys so goldens stay stable across runs."""
    return {k: v for k, v in event.items() if k not in VOLATILE_KEYS}


def run_case(case: GoldenCase) -> list[dict[str, Any]]:
    """Instantiate the case's parser, parse its fixture, return scrubbed events."""
    fixture = case.fixture_path
    if not fixture.exists():
        raise FileNotFoundError(f"fixture missing: {fixture}")

    if case.fixed_mtime is not None:
        # Pin mtime so parsers that stamp events with the file mtime are stable.
        os.utime(fixture, (case.fixed_mtime, case.fixed_mtime))

    ctx = PluginContext(
        case_id="golden",
        job_id="golden",
        source_file_path=fixture,
        source_minio_url=f"file://{fixture}",
        config={},
        logger=logging.getLogger("golden"),
    )
    plugin = case.plugin_cls(ctx)
    plugin.setup()
    try:
        events = [scrub_event(dict(e)) for e in plugin.parse()]
    finally:
        plugin.teardown()

    if case.scrub is not None:
        events = [case.scrub(e) for e in events]
    return events


def load_golden(case: GoldenCase) -> list[dict[str, Any]]:
    return json.loads(case.expected_path.read_text(encoding="utf-8"))


def write_golden(case: GoldenCase, events: list[dict[str, Any]]) -> None:
    case.expected_path.parent.mkdir(parents=True, exist_ok=True)
    case.expected_path.write_text(
        json.dumps(events, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


import re as _re

# ISO-8601 UTC with a Z suffix — the project-wide canonical timestamp form.
_ISO_Z = _re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


def _assert_timestamp_z(event: dict[str, Any]) -> None:
    """Enforce the project-wide ``...Z`` timestamp convention on every event."""
    ts = event.get("timestamp")
    if not isinstance(ts, str) or not _ISO_Z.match(ts):
        raise AssertionError(f"timestamp not ISO-8601 Z: {ts!r}")


def load_schema_validator():
    """Return a callable(event)->None that raises on contract violation.

    Always enforces the required fields + the ``...Z`` timestamp convention via a
    regex (so ``date-time`` is checked even without jsonschema). When jsonschema
    *is* installed, the full ForensicEvent schema is validated WITH a
    ``FormatChecker`` so the schema's ``format: date-time`` is actually honoured
    (jsonschema ignores formats unless a checker is supplied).
    """
    schema_validate = None
    try:
        import jsonschema  # type: ignore

        schema = json.loads(FORENSIC_EVENT_SCHEMA.read_text(encoding="utf-8"))
        checker = jsonschema.FormatChecker()
        validator = jsonschema.Draft202012Validator(schema, format_checker=checker)
        schema_validate = validator.validate
    except ImportError:  # pragma: no cover - minimal envs fall back to regex
        pass

    def _validate(event: dict[str, Any]) -> None:
        if "timestamp" not in event or "message" not in event:
            raise AssertionError("event missing required timestamp/message")
        _assert_timestamp_z(event)
        if schema_validate is not None:
            schema_validate(event)

    return _validate
