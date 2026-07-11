"""Contract tests for the ECS-shaped output the platform produces.

Two producers feed Elasticsearch and the export/import paths, and downstream
consumers (Kibana index templates, the CSV/NDJSON exporter, cross-case search)
rely on a stable field *shape*:

* Rosetta ``normalize_event`` maps a ForensicEvent -> ECS v8 document.
* ``routers.export._flatten_doc`` flattens those ECS docs for CSV export.

These assert required fields exist with the right *types* on representative
records, rather than exact values (which the per-tool unit tests already pin).
Everything here is pure or fakeredis-backed — no live ES/Redis/MinIO.

Mirrors the repo convention: no app boot, helpers called directly, sys.path
seeded the same way the per-tool suites do.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
for _p in (_ROOT / "tools" / "rosetta", _ROOT / "api"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from rosetta.normalize import load_fieldmap, normalize_event  # noqa: E402


@pytest.fixture(scope="module")
def fieldmap():
    return load_fieldmap()


# Representative ForensicEvents across OS families / artifact types. Each must
# normalize to a document that honours the ECS contract below.
REPRESENTATIVE_EVENTS = [
    {
        "timestamp": "2026-01-02T03:04:05Z",
        "message": "A new process has been created.",
        "artifact_type": "windows_event",
        "os": "windows",
        "raw": {
            "EventID": 4688,
            "Computer": "WIN-DC01",
            "TargetUserName": "jdoe",
            "ProcessName": "cmd.exe",
            "ProcessId": 4242,
        },
    },
    {
        "timestamp": "2026-01-02T03:04:05Z",
        "message": "syslogd started",
        "artifact_type": "syslog",
        "os": "linux",
        "raw": {"facility": "daemon"},
    },
    {
        # Minimal event: only the two schema-required fields present.
        "timestamp": "2026-01-02T03:04:05Z",
        "message": "bare event",
    },
]


@pytest.mark.parametrize("event", REPRESENTATIVE_EVENTS)
def test_normalized_doc_honours_ecs_contract(event, fieldmap):
    doc = normalize_event(event, fieldmap, ecs_version="8.11")

    # @timestamp: present, string, ISO-8601 UTC 'Z' form.
    ts = doc["@timestamp"]
    assert isinstance(ts, str) and ts.endswith("Z")

    # message survives verbatim.
    assert doc["message"] == event["message"]

    # ecs.version: string.
    assert doc["ecs"]["version"] == "8.11"

    # event.category / event.type: when present, ECS mandates keyword *arrays*.
    # (A bare event with no artifact_type maps to the empty default and carries
    # no event.* keys — that is a valid document.)
    ev = doc.get("event", {})
    if "category" in ev:
        assert isinstance(ev["category"], list)
        assert all(isinstance(c, str) for c in ev["category"])
    if "type" in ev:
        assert isinstance(ev["type"], list)
        assert all(isinstance(t, str) for t in ev["type"])

    # The raw record is preserved (never silently dropped) under citadel.raw.
    if "raw" in event:
        assert doc["citadel"]["raw"] == event["raw"]


def test_windows_event_maps_typed_process_fields(fieldmap):
    doc = normalize_event(REPRESENTATIVE_EVENTS[0], fieldmap)
    assert doc["host"]["name"] == "WIN-DC01"
    assert doc["user"]["name"] == "jdoe"
    assert doc["process"]["name"] == "cmd.exe"
    # event.code is numeric, process.pid is an int — types matter for ES mapping.
    assert isinstance(doc["event"]["code"], int)
    assert isinstance(doc["process"]["pid"], int)


# ── Export flatten contract (CSV path) ────────────────────────────────────────


def test_flatten_doc_drops_top_level_raw_and_preserves_leaves():
    import routers.export as ex

    doc = normalize_event(REPRESENTATIVE_EVENTS[0], load_fieldmap())
    flat = ex._flatten_doc(doc)

    # Contract: keys are dotted paths; no top-level raw* leaks into the export;
    # nested raw under citadel.* is intentionally represented dotted.
    assert all("." in k or not k.startswith("raw") for k in flat)
    assert not any(k == "raw" for k in flat)

    # ECS leaves survive flattening with dotted keys and scalar/string values.
    assert flat["@timestamp"] == doc["@timestamp"]
    assert flat["host.name"] == "WIN-DC01"
    assert flat["process.name"] == "cmd.exe"

    # Idempotent on the degenerate inputs the exporter must tolerate.
    assert ex._flatten_doc({}) == {}
    assert ex._flatten_doc(None) == {}
