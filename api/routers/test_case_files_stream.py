"""Unit tests for routers/case_files.py streaming read paths.

Follows the api/ colocated-test convention: no FastAPI app boot, handlers called
directly, storage + jobs monkeypatched. Verifies that the converted read paths
pull bytes via storage.stream_object (chunked, no full-object buffer) while
preserving the pre-flight stat_object behaviour and byte-for-byte results.
"""

import asyncio
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import routers.case_files as cf  # noqa: E402


def _drain(resp) -> bytes:
    async def _run():
        chunks = []
        async for c in resp.body_iterator:
            chunks.append(c.encode() if isinstance(c, str) else c)
        return b"".join(chunks)

    return asyncio.run(_run())


@pytest.fixture
def stub_storage(monkeypatch):
    calls = {"download_fileobj": 0}

    def _no_buffer(*a, **k):
        calls["download_fileobj"] += 1
        raise AssertionError("download_fileobj must not be used on stream paths")

    monkeypatch.setattr(cf.storage, "download_fileobj", _no_buffer, raising=True)
    return calls


def test_get_file_content_streams_object(monkeypatch, stub_storage):
    payload = b"line one\nline two\n"
    monkeypatch.setattr(
        cf.job_svc,
        "get_job",
        lambda jid: {"case_id": "c1", "original_filename": "notes.txt", "minio_object_key": "k1"},
        raising=True,
    )
    monkeypatch.setattr(
        cf.storage, "stat_object", lambda key: types.SimpleNamespace(size=len(payload)), raising=True
    )
    monkeypatch.setattr(
        cf.storage, "stream_object", lambda key: iter([payload[:5], payload[5:]]), raising=True
    )

    out = cf.get_file_content("c1", "j1", _case={})
    assert out["content"] == payload.decode()
    assert out["size_bytes"] == len(payload)
    assert stub_storage["download_fileobj"] == 0


def test_get_file_content_rejects_oversize_without_download(monkeypatch, stub_storage):
    monkeypatch.setattr(
        cf.job_svc,
        "get_job",
        lambda jid: {"case_id": "c1", "original_filename": "notes.txt", "minio_object_key": "k1"},
        raising=True,
    )
    monkeypatch.setattr(
        cf.storage,
        "stat_object",
        lambda key: types.SimpleNamespace(size=cf._MAX_VIEW_BYTES + 1),
        raising=True,
    )

    def _boom(key):
        raise AssertionError("oversize file must not be streamed")

    monkeypatch.setattr(cf.storage, "stream_object", _boom, raising=True)

    with pytest.raises(cf.HTTPException) as ei:
        cf.get_file_content("c1", "j1", _case={})
    assert ei.value.status_code == 413
