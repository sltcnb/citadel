"""Unit tests for the Sluice bus-emit + idempotent re-ingest logic.

Covered:
  * Idempotency dedup on artifact sha256 (mark_and_check_seen).
  * events.parsed emit serializes a valid forensic_event/v1 payload.
  * Feature flag gates emit so the existing flow is untouched when disabled.

No redis server or redis-py needed — see conftest.FakeRedis.
"""

from __future__ import annotations

import json
from pathlib import Path

import bus_emit
import pytest

# ── Idempotency ────────────────────────────────────────────────────────────────


def test_dedup_first_seen_is_new_then_skipped(fake_redis):
    sha = "a" * 64
    # First time: new -> returns False (proceed).
    assert bus_emit.mark_and_check_seen(fake_redis, "case1", sha) is False
    # Re-ingest of the same sha256: already seen -> returns True (skip).
    assert bus_emit.mark_and_check_seen(fake_redis, "case1", sha) is True
    assert bus_emit.mark_and_check_seen(fake_redis, "case1", sha) is True


def test_dedup_is_scoped_per_case(fake_redis):
    sha = "b" * 64
    assert bus_emit.mark_and_check_seen(fake_redis, "caseA", sha) is False
    # Same sha in a different case is independent — must not be skipped.
    assert bus_emit.mark_and_check_seen(fake_redis, "caseB", sha) is False
    # But a second hit in caseA is.
    assert bus_emit.mark_and_check_seen(fake_redis, "caseA", sha) is True


def test_dedup_sets_ttl(fake_redis):
    sha = "c" * 64
    bus_emit.mark_and_check_seen(fake_redis, "case1", sha)
    key = bus_emit._dedup_set_key("case1")
    assert fake_redis.expires.get(key) == bus_emit.DEDUP_TTL_SECONDS


def test_forget_seen_allows_reingest_after_failure(fake_redis):
    sha = "d" * 64
    assert bus_emit.mark_and_check_seen(fake_redis, "case1", sha) is False
    # Simulate the ingest failing before producing events -> release the claim.
    bus_emit.forget_seen(fake_redis, "case1", sha)
    # A genuine retry must be treated as new, not permanently skipped.
    assert bus_emit.mark_and_check_seen(fake_redis, "case1", sha) is False


def test_empty_sha_never_skips(fake_redis):
    assert bus_emit.mark_and_check_seen(fake_redis, "case1", "") is False


def test_compute_sha256(tmp_path):
    p = tmp_path / "artifact.bin"
    p.write_bytes(b"hello citadel")
    import hashlib

    assert bus_emit.compute_sha256(p) == hashlib.sha256(b"hello citadel").hexdigest()


# ── forensic_event/v1 serialization ─────────────────────────────────────────────

# Load the shared contract once so the test enforces the real required list.
_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "contracts" / "forensic_event.schema.json"
_SCHEMA = json.loads(_SCHEMA_PATH.read_text())


def _assert_valid_forensic_event_v1(fo: dict) -> None:
    """Validate against the real contract — with jsonschema if available, else
    a focused manual check that mirrors forensic_event.schema.json."""
    try:
        import jsonschema  # type: ignore

        jsonschema.validate(instance=fo, schema=_SCHEMA)
        return
    except ImportError:
        pass
    # Manual fallback mirroring the schema's constraints.
    for req in _SCHEMA["required"]:
        assert isinstance(fo.get(req), str) and fo[req].strip(), f"missing/blank {req}"
    if "raw" in fo:
        assert isinstance(fo["raw"], (dict, str))
    if "os" in fo:
        assert fo["os"] in _SCHEMA["properties"]["os"]["enum"]


def test_to_forensic_event_v1_projects_contract_fields():
    internal = {
        "fo_id": "deadbeef",
        "case_id": "c1",
        "ingest_job_id": "j1",
        "source_file": "minio://bucket/cases/c1/j1/Security.evtx",
        "ingested_at": "2026-06-08T00:00:00+00:00",
        "timestamp": "2026-06-08T12:00:00+00:00",
        "timestamp_desc": "logon",
        "message": "User bob logged on",
        "artifact_type": "windows_event",
        "os": "windows",
        "parser": "evtx",
        "raw": {"EventID": 4624, "user": "bob"},
        "host": {"hostname": "WS01"},  # ES-only field, dropped from the wire payload
    }
    fo = bus_emit.to_forensic_event_v1(internal)
    _assert_valid_forensic_event_v1(fo)
    # Contract fields survive.
    assert fo["timestamp"] == internal["timestamp"]
    assert fo["message"] == internal["message"]
    assert fo["artifact_type"] == "windows_event"
    assert fo["raw"] == {"EventID": 4624, "user": "bob"}
    # internal source_file maps to the contract's source_path.
    assert fo["source_path"] == internal["source_file"]
    # ES-only bookkeeping is not carried onto the bus.
    assert "fo_id" not in fo and "host" not in fo and "case_id" not in fo


def test_to_forensic_event_v1_fills_required_when_missing():
    fo = bus_emit.to_forensic_event_v1({"artifact_type": "generic"})
    _assert_valid_forensic_event_v1(fo)
    assert fo["message"] == "generic"
    assert isinstance(fo["timestamp"], str) and fo["timestamp"]


def test_validate_rejects_bad_payloads():
    with pytest.raises(ValueError):
        bus_emit.validate_forensic_event_v1({"message": "x"})  # no timestamp
    with pytest.raises(ValueError):
        bus_emit.validate_forensic_event_v1({"timestamp": "2026-01-01T00:00:00Z", "message": ""})
    with pytest.raises(ValueError):
        bus_emit.validate_forensic_event_v1(
            {"timestamp": "2026-01-01T00:00:00Z", "message": "ok", "os": "solaris"}
        )
    with pytest.raises(ValueError):
        bus_emit.validate_forensic_event_v1(
            {"timestamp": "2026-01-01T00:00:00Z", "message": "ok", "raw": 123}
        )


def test_serialize_batch_shape_and_validity():
    events = [
        {"timestamp": "2026-06-08T12:00:00+00:00", "message": "a", "artifact_type": "syslog"},
        {"timestamp": "2026-06-08T12:00:01+00:00", "message": "b", "artifact_type": "syslog"},
    ]
    fields = bus_emit.serialize_batch(events, case_id="c1", job_id="j1", company="acme")
    assert fields["schema"] == "forensic_event/v1"
    assert fields["topic"] == "events.parsed"
    assert fields["case_id"] == "c1"
    assert fields["company"] == "acme"
    assert fields["count"] == "2"
    decoded = json.loads(fields["events"])
    assert len(decoded) == 2
    for fo in decoded:
        _assert_valid_forensic_event_v1(fo)


# ── emit (bus side channel) ──────────────────────────────────────────────────────


def test_emit_disabled_is_noop(fake_redis, monkeypatch):
    monkeypatch.delenv("BUS_EMIT_ENABLED", raising=False)
    written = bus_emit.emit_events_parsed(
        fake_redis,
        [{"timestamp": "2026-06-08T12:00:00+00:00", "message": "a"}],
        case_id="c1",
        job_id="j1",
    )
    assert written == 0
    assert fake_redis.streams == {}  # nothing published when flag is off


def test_emit_enabled_writes_valid_stream_entry(fake_redis, monkeypatch):
    monkeypatch.setenv("BUS_EMIT_ENABLED", "1")
    events = [
        {
            "timestamp": "2026-06-08T12:00:00+00:00",
            "message": "a",
            "artifact_type": "syslog",
            "os": "linux",
            "raw": {"k": "v"},
        },
    ]
    written = bus_emit.emit_events_parsed(
        fake_redis, events, case_id="c1", job_id="j1", company="acme"
    )
    assert written == 1
    stream = bus_emit.events_parsed_stream("acme")
    entries = fake_redis.xrange(stream)
    assert len(entries) == 1
    _entry_id, fields = entries[0]
    assert fields["schema"] == "forensic_event/v1"
    payload = json.loads(fields["events"])
    assert len(payload) == 1
    _assert_valid_forensic_event_v1(payload[0])


def test_emit_batches_when_over_batch_size(fake_redis, monkeypatch):
    monkeypatch.setenv("BUS_EMIT_ENABLED", "1")
    monkeypatch.setattr(bus_emit, "EMIT_BATCH_SIZE", 2)
    events = [{"timestamp": "2026-06-08T12:00:00+00:00", "message": f"m{i}"} for i in range(5)]
    written = bus_emit.emit_events_parsed(fake_redis, events, case_id="c1", job_id="j1")
    # 5 events / batch of 2 -> ceil = 3 stream entries.
    assert written == 3
    total = sum(
        len(json.loads(f["events"]))
        for _, f in fake_redis.xrange(bus_emit.events_parsed_stream(None))
    )
    assert total == 5


def test_emit_failure_is_swallowed(monkeypatch):
    monkeypatch.setenv("BUS_EMIT_ENABLED", "1")

    class BoomRedis:
        def xadd(self, *a, **k):
            raise RuntimeError("redis down")

    # Must not raise — bus emit is a side channel.
    written = bus_emit.emit_events_parsed(
        BoomRedis(),
        [{"timestamp": "2026-06-08T12:00:00+00:00", "message": "a"}],
        case_id="c1",
        job_id="j1",
    )
    assert written == 0


def test_stream_key_tenant_isolation():
    assert bus_emit.events_parsed_stream("acme") == "bus:events.parsed:acme"
    assert bus_emit.events_parsed_stream(None) == "bus:events.parsed:_global"
    assert bus_emit.events_parsed_stream("") == "bus:events.parsed:_global"
