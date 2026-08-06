"""Contract guard: hollow (null-content) events are rejected, whatever the source.

Covers the junk-row class observed in real cases — e.g. the plist parser
dumping ``core.xml: <null>`` for an OOXML part it could not parse. The guard
lives in ``_validate_event`` so every ingest path (direct upload, ZIP/TAR
bundle expansion, S3 triage pull) is covered centrally.
"""

from __future__ import annotations

import pytest

from tasks import ingest_task


def _validate(event: dict) -> dict:
    return ingest_task._validate_event(event, "plist", "job1")


# ── _event_is_hollow: detection ───────────────────────────────────────────────


def test_hollow_filename_null_row_is_detected():
    ev = {
        "message": "core.xml: <null>",
        "artifact_type": "plist",
        "plist": {"filename": "core.xml", "value": None},
        "raw": {"filename": "core.xml", "value": None},
    }
    assert ingest_task._event_is_hollow(ev) is True


def test_hollow_keyed_null_row_is_detected():
    ev = {
        "message": "config.json | theme: <null>",
        "artifact_type": "json",
        "json": {"key": "theme", "value": None},
        "raw": {"key": "theme", "value": None},
    }
    assert ingest_task._event_is_hollow(ev) is True


def test_bare_null_message_is_hollow():
    assert ingest_task._event_is_hollow({"message": "<null>", "raw": {"value": None}}) is True


# ── _event_is_hollow: rows with real content must survive ─────────────────────


def test_row_with_real_value_is_not_hollow():
    ev = {
        "message": "com.apple.dock.plist | orientation = left",
        "artifact_type": "plist",
        "plist": {"filename": "com.apple.dock.plist", "key": "orientation", "value": "left"},
        "raw": {"filename": "com.apple.dock.plist", "key": "orientation", "value": "left"},
    }
    assert ingest_task._event_is_hollow(ev) is False


def test_null_in_middle_of_message_is_not_hollow():
    ev = {"message": "parsed <null> literal from config.json", "raw": {"line": "x"}}
    assert ingest_task._event_is_hollow(ev) is False


def test_zero_and_false_are_content_not_hollow():
    ev = {
        "message": "settings.json | retries: 0",
        "artifact_type": "json",
        "raw": {"key": "retries", "value": 0},
    }
    assert ingest_task._event_is_hollow(ev) is False


def test_raw_line_payload_is_content_not_hollow():
    # ios-style events carry the full record as a JSON string in raw.line
    ev = {
        "message": "backup.plist: <null>",
        "artifact_type": "plist",
        "raw": {"line": '{"key": "a", "value": 1}'},
    }
    assert ingest_task._event_is_hollow(ev) is False


# ── _validate_event: enforcement ─────────────────────────────────────────────


def test_validate_event_rejects_hollow_row():
    ev = {
        "message": "core.xml: <null>",
        "artifact_type": "plist",
        "raw": {"filename": "core.xml", "value": None},
    }
    with pytest.raises(ValueError, match="hollow event"):
        _validate(ev)
    assert ingest_task._validation_warnings.get("plist:hollow_event", 0) >= 1


def test_validate_event_keeps_normal_row():
    ev = {
        "message": "com.apple.dock.plist | orientation = left",
        "artifact_type": "plist",
        "plist": {"filename": "com.apple.dock.plist", "key": "orientation", "value": "left"},
        "raw": {"filename": "com.apple.dock.plist", "key": "orientation", "value": "left"},
    }
    out = _validate(dict(ev))
    assert out["message"] == ev["message"]
