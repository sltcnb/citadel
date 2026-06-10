#!/usr/bin/env python3
"""
Offline unit tests for the Talon resumable chunker (agent_client).

No gRPC, no server: we feed a temp blob through iter_chunks / ChunkUploader and
verify sha256 (full + per-chunk), 8 MiB framing, the last-chunk terminator, and
resume-from-offset reconstruction.

Run:
    pytest tools/talon/tests/test_chunker.py
or standalone:
    python tools/talon/tests/test_chunker.py
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

# Make agent_client importable when run via pytest or directly.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_client import (  # noqa: E402
    CHUNK_SIZE,
    ChunkUploader,
    UploadAck,
    UploadError,
    blob_sha256,
    chunk_sha256,
    iter_chunks,
)


def _write_blob(path: Path, size: int) -> bytes:
    data = os.urandom(size) if size else b""
    path.write_bytes(data)
    return data


def test_full_and_per_chunk_sha256(tmp_path):
    data = _write_blob(tmp_path / "blob.bin", int(CHUNK_SIZE * 2.5))
    full = hashlib.sha256(data).hexdigest()

    chunks = list(iter_chunks(tmp_path / "blob.bin", session_id="s1"))
    assert len(chunks) == 3  # 8M + 8M + 4M
    # Every chunk carries the same full-blob digest and a correct per-chunk digest.
    for c in chunks:
        assert c.blob_sha256 == full
        assert c.chunk_sha256 == chunk_sha256(c.data)
        assert c.session_id == "s1"
    # Framing: first two are exactly 8 MiB, only the last is flagged.
    assert len(chunks[0].data) == CHUNK_SIZE
    assert len(chunks[1].data) == CHUNK_SIZE
    assert chunks[0].last is False and chunks[1].last is False
    assert chunks[-1].last is True
    # Offsets are contiguous and cover the whole blob.
    assert chunks[0].offset == 0
    assert chunks[1].offset == CHUNK_SIZE
    assert chunks[2].offset == 2 * CHUNK_SIZE
    reassembled = b"".join(c.data for c in chunks)
    assert reassembled == data
    assert hashlib.sha256(reassembled).hexdigest() == full
    assert blob_sha256(tmp_path / "blob.bin") == full


def test_exact_multiple_marks_last(tmp_path):
    _write_blob(tmp_path / "exact.bin", CHUNK_SIZE * 2)
    chunks = list(iter_chunks(tmp_path / "exact.bin", session_id="s"))
    assert len(chunks) == 2
    assert chunks[0].last is False
    assert chunks[1].last is True
    assert chunks[1].offset == CHUNK_SIZE


def test_empty_blob_yields_terminator(tmp_path):
    _write_blob(tmp_path / "empty.bin", 0)
    chunks = list(iter_chunks(tmp_path / "empty.bin", session_id="s"))
    assert len(chunks) == 1
    assert chunks[0].data == b""
    assert chunks[0].last is True
    assert chunks[0].chunk_sha256 == hashlib.sha256(b"").hexdigest()


def test_resume_from_offset(tmp_path):
    size = int(CHUNK_SIZE * 2.5)
    data = _write_blob(tmp_path / "resume.bin", size)
    full = hashlib.sha256(data).hexdigest()

    # Pretend the server already accepted the first 8 MiB chunk.
    resume = CHUNK_SIZE
    chunks = list(iter_chunks(tmp_path / "resume.bin", session_id="s", start_offset=resume))
    assert len(chunks) == 2  # remaining 8M + 4M
    assert chunks[0].offset == resume
    # Resumed stream still reports the *full* blob digest, not a partial one.
    assert all(c.blob_sha256 == full for c in chunks)
    # The resumed bytes match the tail of the original blob.
    tail = b"".join(c.data for c in chunks)
    assert tail == data[resume:]
    assert chunks[-1].last is True


def test_resume_offset_out_of_range(tmp_path):
    _write_blob(tmp_path / "x.bin", 1024)
    try:
        list(iter_chunks(tmp_path / "x.bin", session_id="s", start_offset=99999))
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_uploader_drives_offline_transport(tmp_path):
    """ChunkUploader.upload should stream every chunk through an injected sink."""
    data = _write_blob(tmp_path / "u.bin", int(CHUNK_SIZE * 1.5))
    sink = bytearray()

    def fake_send(chunks):
        received = 0
        digest = None
        for c in chunks:
            assert c.chunk_sha256 == chunk_sha256(c.data)
            assert c.offset == received  # contiguous
            sink.extend(c.data)
            received += len(c.data)
            digest = c.blob_sha256
        return UploadAck(
            session_id=c.session_id,
            bytes_received=received,
            verified=(hashlib.sha256(bytes(sink)).hexdigest() == digest),
        )

    up = ChunkUploader(tmp_path / "u.bin", session_id="up1")
    ack = up.upload(send=fake_send)
    assert ack.verified is True
    assert ack.bytes_received == len(data)
    assert bytes(sink) == data
    assert up.bytes_sent == len(data)


def test_uploader_resume_then_complete(tmp_path):
    """A resumed upload re-sends only the tail and still verifies against the full digest."""
    size = int(CHUNK_SIZE * 2.5)
    data = _write_blob(tmp_path / "r.bin", size)
    full = hashlib.sha256(data).hexdigest()

    # First leg: server accepts one chunk then "drops".
    accepted = bytearray()

    def send_first(chunks):
        c = next(chunks)
        accepted.extend(c.data)
        return UploadAck(
            session_id=c.session_id, bytes_received=len(accepted), error="connection reset"
        )

    up1 = ChunkUploader(tmp_path / "r.bin", session_id="r1")
    try:
        up1.upload(send=send_first)
        assert False, "expected UploadError"
    except UploadError:
        pass

    # Resume from what the server kept.
    def send_rest(chunks):
        for c in chunks:
            accepted.extend(c.data)
        return UploadAck(
            session_id=c.session_id,
            bytes_received=len(accepted),
            verified=(hashlib.sha256(bytes(accepted)).hexdigest() == full),
        )

    up2 = ChunkUploader(tmp_path / "r.bin", session_id="r1", resume_offset=len(accepted))
    ack = up2.upload(send=send_rest)
    assert ack.verified is True
    assert bytes(accepted) == data


def test_uploader_byte_mismatch_raises(tmp_path):
    _write_blob(tmp_path / "m.bin", 4096)

    def bad_send(chunks):
        for _ in chunks:
            pass
        return UploadAck(bytes_received=1)  # wrong count

    up = ChunkUploader(tmp_path / "m.bin", session_id="m")
    try:
        up.upload(send=bad_send)
        assert False, "expected UploadError"
    except UploadError:
        pass


if __name__ == "__main__":
    import tempfile
    import traceback

    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        with tempfile.TemporaryDirectory() as d:
            try:
                fn(Path(d))
                print(f"PASS  {fn.__name__}")
            except Exception:
                failed += 1
                print(f"FAIL  {fn.__name__}")
                traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
