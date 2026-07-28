"""Regression tests: .citadel archive import hardening.

Covers the three audit findings on the import path:
  1. Archive-supplied job ids were trusted verbatim — a crafted archive could
     overwrite a VICTIM case's job:{id} record (chain-of-custody tampering).
     Import now mints fresh ids and keeps the original as prior_job_id.
  2. Tar members were slurped fully decompressed into RAM — a gz bomb OOMed
     the API pod. Reads are now size-capped and events are streamed.
  3. The import route was guest-reachable. Guests now get 403.
"""

import asyncio
import gzip
import io
import json
import sys
import tarfile
from pathlib import Path

import fakeredis
import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import routers.export as ex  # noqa: E402


@pytest.fixture
def export_redis(monkeypatch):
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(ex, "get_redis", lambda: fake, raising=True)
    return fake


def _write_archive(path, jobs=None, notes=None, events=None):
    manifest = {
        "format": ex.ARCHIVE_FORMAT,
        "case_id": "oldcase",
        "exported_at": "2026-01-01T00:00:00Z",
        "event_count": len(events or []),
        "job_count": len(jobs or []),
    }
    members = {
        "manifest.json": json.dumps(manifest).encode(),
        "case.json": json.dumps({"name": "Imported Case"}).encode(),
        "jobs.json": json.dumps(jobs or []).encode(),
        "notes.json": json.dumps(notes or {}).encode(),
        "alert_rules.json": b"[]",
        "saved_searches.json": b"[]",
    }
    if events is not None:
        members["events.ndjson.gz"] = gzip.compress(
            b"".join(json.dumps(e).encode() + b"\n" for e in events)
        )
    with tarfile.open(path, "w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def test_import_remints_job_ids(export_redis, tmp_path):
    """A crafted archive naming a victim job_id must not touch its record."""
    victim_jid = "a" * 32
    export_redis.hset(
        f"job:{victim_jid}",
        mapping={"job_id": victim_jid, "case_id": "victimcase", "sha256": "deadbeef", "status": "COMPLETED"},
    )
    archive = tmp_path / "evil.citadel"
    _write_archive(
        archive,
        jobs=[{"job_id": victim_jid, "case_id": "victimcase", "sha256": "0" * 64, "status": "COMPLETED"}],
    )
    result = ex._import_archive_file(str(archive))

    # Victim record untouched — chain of custody intact.
    assert export_redis.hget(f"job:{victim_jid}", "case_id") == "victimcase"
    assert export_redis.hget(f"job:{victim_jid}", "sha256") == "deadbeef"

    # The imported job got a fresh id bound to the new case, original kept as provenance.
    new_jids = export_redis.smembers(f"case:{result['case_id']}:jobs")
    assert len(new_jids) == 1
    new_jid = next(iter(new_jids))
    assert new_jid != victim_jid
    assert export_redis.hget(f"job:{new_jid}", "prior_job_id") == victim_jid
    assert export_redis.hget(f"job:{new_jid}", "case_id") == result["case_id"]


def test_oversized_metadata_member_rejected(export_redis, tmp_path, monkeypatch):
    monkeypatch.setattr(ex, "_MAX_IMPORT_MEMBER_BYTES", 2048, raising=True)
    archive = tmp_path / "big.citadel"
    _write_archive(archive, notes={"body": "x" * 5000})
    with pytest.raises(HTTPException) as exc:
        ex._import_archive_file(str(archive))
    assert exc.value.status_code == 413


def test_events_bomb_capped(export_redis, tmp_path, monkeypatch):
    monkeypatch.setattr(ex, "_MAX_IMPORT_EVENTS_BYTES", 4096, raising=True)
    archive = tmp_path / "bomb.citadel"
    _write_archive(archive, events=[{"message": "A" * 2048} for _ in range(4)])
    with pytest.raises(HTTPException) as exc:
        ex._import_archive_file(str(archive))
    assert exc.value.status_code == 413


def test_import_guest_denied():
    class _File:  # minimal UploadFile stand-in — must never be read for guests
        async def read(self, n=-1):
            raise AssertionError("guest upload reached the spool")

    with pytest.raises(HTTPException) as exc:
        asyncio.run(ex.import_archive(_File(), {"role": "guest", "username": "g"}))
    assert exc.value.status_code == 403


def test_import_analyst_allowed(export_redis, tmp_path):
    archive = tmp_path / "ok.citadel"
    _write_archive(archive, events=[{"message": "hello", "artifact_type": "evtx"}])

    class _File:
        def __init__(self, data):
            self._chunks = [data]

        async def read(self, n=-1):
            return self._chunks.pop(0) if self._chunks else b""

    # Bulk indexing goes to ES — stub it out; we only exercise auth + spool + parse.
    import routers.export as _ex

    orig = _ex._bulk_index_events
    _ex._bulk_index_events = lambda cid, stream: 1
    try:
        result = asyncio.run(
            ex.import_archive(_File(archive.read_bytes()), {"role": "analyst", "username": "a"})
        )
    finally:
        _ex._bulk_index_events = orig
    assert result["events_imported"] == 1
