"""Chunked-upload integrity tests for routers/ingest.py::ingest_chunk.

Covers the hardening added to the chunk endpoint:
  * 400 on out-of-range chunk_index / total_chunks;
  * 409 when a chunk index is resent for the same upload_id (double-append
    would corrupt the assembly);
  * 400 when the final chunk arrives with earlier chunks still missing;
  * the assembled byte total must match the per-chunk ledger;
  * abandoned chunk files older than 24h are swept at finalize time.

Handlers are called directly (api/ colocated-test convention) — no FastAPI app
boot; case lookup, job service and the chunk dir are monkeypatched.
"""

import asyncio
import io
import os
import sys
import time
from pathlib import Path

import pytest
from fastapi import BackgroundTasks, HTTPException, UploadFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import routers.ingest as ing  # noqa: E402


@pytest.fixture
def env(monkeypatch, tmp_path):
    chunk_dir = tmp_path / "_chunks"
    monkeypatch.setattr(ing, "_CHUNK_DIR", chunk_dir)
    monkeypatch.setattr(ing, "get_case", lambda cid: {"case_id": cid, "status": "active"})
    monkeypatch.setattr(ing.job_svc, "create_job", lambda *a, **k: {})
    monkeypatch.setattr(ing.job_svc, "update_job", lambda *a, **k: None)
    return chunk_dir


def _upload(data: bytes) -> UploadFile:
    return UploadFile(file=io.BytesIO(data), filename="chunk")


def _post(upload_id="abcdef0123456789", filename="big.evtx", index=0, total=1, data=b"x"):
    return asyncio.run(
        ing.ingest_chunk(
            case_id="c1",
            upload_id=upload_id,
            filename=filename,
            chunk_index=index,
            total_chunks=total,
            chunk=_upload(data),
            keep_raw=False,
            background_tasks=BackgroundTasks(),
            _case={},
        )
    )


def test_rejects_total_chunks_zero(env):
    with pytest.raises(HTTPException) as ei:
        _post(index=0, total=0)
    assert ei.value.status_code == 400


def test_rejects_total_chunks_above_cap(env):
    with pytest.raises(HTTPException) as ei:
        _post(index=0, total=ing._MAX_CHUNKS + 1)
    assert ei.value.status_code == 400


def test_rejects_negative_chunk_index(env):
    with pytest.raises(HTTPException) as ei:
        _post(index=-1, total=3)
    assert ei.value.status_code == 400


def test_rejects_chunk_index_out_of_range(env):
    with pytest.raises(HTTPException) as ei:
        _post(index=3, total=3)  # valid indexes are 0..2
    assert ei.value.status_code == 400


def test_partial_chunks_acknowledged(env):
    out = _post(index=0, total=3, data=b"aaa")
    assert out["status"] == "partial"
    out = _post(index=1, total=3, data=b"bbb")
    assert out["status"] == "partial"
    assert out["received"] == 2


def test_double_append_same_chunk_rejected(env):
    _post(index=0, total=2, data=b"aaa")
    with pytest.raises(HTTPException) as ei:
        _post(index=0, total=2, data=b"aaa")
    assert ei.value.status_code == 409


def test_final_chunk_with_missing_earlier_chunk_rejected(env):
    _post(index=0, total=3, data=b"aaa")
    with pytest.raises(HTTPException) as ei:
        _post(index=2, total=3, data=b"ccc")  # chunk 1 never sent
    assert ei.value.status_code == 400
    assert "missing" in ei.value.detail.lower()


def test_happy_path_assembles_and_dispatches(env):
    _post(index=0, total=3, data=b"aaa")
    _post(index=1, total=3, data=b"bbb")
    out = _post(index=2, total=3, data=b"ccc")
    assert out["case_id"] == "c1"
    assert len(out["jobs"]) == 1
    job = out["jobs"][0]
    assert job["filename"] == "big.evtx"
    assert job["size_bytes"] == 9  # aaa+bbb+ccc
    assert job["status"] == "UPLOADING"
    # Ledger removed once the assembly is verified and handed off.
    leftover = list(env.glob("*.chunks.json"))
    assert leftover == []


def test_stale_chunk_files_swept_at_finalize(env):
    chunk_dir = env
    chunk_dir.mkdir(parents=True, exist_ok=True)
    stale = chunk_dir / "deadbeef00_old.evtx"
    stale.write_bytes(b"orphan bytes")
    old = time.time() - (ing._CHUNK_STALE_SECONDS + 60)
    os.utime(stale, (old, old))

    _post(index=0, total=1, data=b"x")  # finalize an unrelated upload

    assert not stale.exists()


def test_recent_partial_upload_not_swept(env):
    _post(upload_id="1111222233334444", index=0, total=5, data=b"part")
    _post(index=0, total=1, data=b"x")  # finalize another upload → sweep runs
    # The in-flight assembly (well under 24h old) survives the sweep.
    assert list(env.glob("1111222233334444_*"))
