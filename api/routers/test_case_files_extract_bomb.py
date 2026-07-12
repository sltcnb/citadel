"""Decompression-bomb defenses for ``routers.case_files.extract_archive_member``.

Follows the api/ colocated-test convention: no FastAPI app boot — the handler is
called directly with ``job_svc.get_job`` and ``storage.stream_object`` mocked,
and the per-member cap lowered via the module constant the code reads
(``MAX_EXTRACT_MEMBER_BYTES`` populates it at import).

Covers:
  * a member whose *declared* size exceeds the cap → HTTP 413;
  * a member that *lies* (small declared, large actual) → aborted mid-copy → 413;
  * a legitimate member streams out fully.
"""

from __future__ import annotations

import asyncio
import io
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import routers.case_files as cf  # noqa: E402


# ── helpers ────────────────────────────────────────────────────────────────


def _zip_bytes(members: dict[str, bytes], *, stored: bool = False) -> bytes:
    buf = io.BytesIO()
    comp = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(buf, "w", compression=comp) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _drain(resp) -> bytes:
    async def _run():
        chunks = []
        async for c in resp.body_iterator:
            chunks.append(c.encode() if isinstance(c, str) else c)
        return b"".join(chunks)

    return asyncio.run(_run())


@pytest.fixture
def wired(monkeypatch):
    """Wire job_svc + storage so extract_archive_member can run headless.

    Returns a setter: call ``set_archive(bytes)`` to control what the mocked
    ``storage.stream_object`` yields for the archive object.
    """
    state = {"archive": b""}

    monkeypatch.setattr(
        cf.job_svc,
        "get_job",
        lambda jid: {
            "case_id": "case1",
            "minio_object_key": "cases/case1/arc.zip",
            "original_filename": "arc.zip",
        },
        raising=True,
    )

    def _stream(_key):
        yield state["archive"]

    monkeypatch.setattr(cf.storage, "stream_object", _stream, raising=True)

    def _set(data: bytes):
        state["archive"] = data

    return _set


def _call(member: str):
    return cf.extract_archive_member(
        case_id="case1", job_id="job1", member=member, _case={}
    )


# ── (a) declared size > cap → 413 ────────────────────────────────────────────


def test_declared_oversize_member_rejected_413(wired, monkeypatch):
    monkeypatch.setattr(cf, "_MAX_EXTRACT_MEMBER_BYTES", 128)
    wired(_zip_bytes({"big.txt": b"A" * 8192}))

    with pytest.raises(HTTPException) as ei:
        _call("big.txt")
    assert ei.value.status_code == 413
    assert "too large" in ei.value.detail.lower()


# ── (b) size-lie aborted mid-copy → 413 ──────────────────────────────────────


def test_bounded_copy_aborts_when_actual_exceeds_cap():
    """The running byte counter aborts the copy the moment actual bytes cross the
    cap — a member that lied about its declared size cannot inflate past it."""
    cap = 4096
    src = io.BytesIO(b"Z" * (cap * 4))
    dst = io.BytesIO()
    with pytest.raises(ValueError, match="extraction size cap"):
        cf._bounded_copy(src, dst, cap)
    # Stopped shortly after crossing the cap, not after slurping the whole stream.
    assert dst.tell() <= cap + 1024 * 1024


def test_size_lie_aborted_midcopy_maps_to_413(wired, monkeypatch):
    """When the mid-copy guard (``_bounded_copy``) trips on a member that lied
    about its declared size, the endpoint surfaces it as HTTP 413."""
    monkeypatch.setattr(cf, "_MAX_EXTRACT_MEMBER_BYTES", 4096)
    wired(_zip_bytes({"liar.bin": b"Z" * 64}))

    # Simulate the streamed member exceeding the cap partway through the copy —
    # exactly what a decompression bomb triggers inside _bounded_copy.
    def _lying_copy(src, dst, limit):
        raise ValueError(f"member exceeds extraction size cap ({limit} bytes)")

    monkeypatch.setattr(cf, "_bounded_copy", _lying_copy, raising=True)

    with pytest.raises(HTTPException) as ei:
        _call("liar.bin")
    assert ei.value.status_code == 413
    assert "cap" in ei.value.detail.lower()


# ── (c) legitimate member streams out fully ──────────────────────────────────


def test_legitimate_member_streams_out(wired, monkeypatch):
    monkeypatch.setattr(cf, "_MAX_EXTRACT_MEMBER_BYTES", 1024 * 1024)
    body = b"hello, forensic world\n" * 10
    wired(_zip_bytes({"notes/report.txt": body, "other.txt": b"x"}))

    resp = _call("notes/report.txt")
    assert resp.status_code == 200
    assert _drain(resp) == body


def test_missing_member_404(wired, monkeypatch):
    monkeypatch.setattr(cf, "_MAX_EXTRACT_MEMBER_BYTES", 1024 * 1024)
    wired(_zip_bytes({"present.txt": b"x"}))

    with pytest.raises(HTTPException) as ei:
        _call("absent.txt")
    assert ei.value.status_code == 404
