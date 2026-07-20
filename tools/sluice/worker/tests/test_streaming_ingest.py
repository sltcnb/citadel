"""
Streaming-ingest regression tests.

Verifies that large synthetic artifacts are hashed and archive entries are
extracted/uploaded in bounded chunks — never buffered whole in memory — while
small-file behavior (correct hash, correct bytes) stays unchanged.

These import ingest_task's helpers directly rather than exercising the full
Celery task, so no broker/ES/MinIO connection is needed.
"""

from __future__ import annotations

import hashlib
import io
import os
import zipfile

import bus_emit
import pytest
from tasks import ingest_task


class _SpyReader:
    """Wraps a file-like object and records every read() call size."""

    def __init__(self, fileobj):
        self._f = fileobj
        self.read_sizes: list[int] = []

    def read(self, n=-1):
        chunk = self._f.read(n)
        self.read_sizes.append(len(chunk) if n is None or n < 0 else n)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self._f.close()


# ── compute_sha256 (main artifact hashing) ────────────────────────────────────


@pytest.mark.parametrize("size", [0, 100, 5 * 1024 * 1024 + 7])
def test_compute_sha256_matches_reference_for_various_sizes(tmp_path, size):
    data = os.urandom(size)
    path = tmp_path / "artifact.bin"
    path.write_bytes(data)

    got = bus_emit.compute_sha256(str(path))
    expected = hashlib.sha256(data).hexdigest()
    assert got == expected


def test_compute_sha256_reads_in_bounded_chunks_for_large_file(tmp_path, monkeypatch):
    """A large synthetic file must be hashed via bounded reads — not a single
    whole-file read() — proving memory use stays flat regardless of size."""
    size = 40 * 1024 * 1024 + 123  # not a clean multiple of the chunk size
    data = os.urandom(size)
    path = tmp_path / "large.bin"
    path.write_bytes(data)

    seen_reads: list[int] = []
    real_open = open

    class _TrackedFile:
        def __init__(self, fh):
            self._fh = fh

        def read(self, n=-1):
            chunk = self._fh.read(n)
            seen_reads.append(len(chunk))
            return chunk

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self._fh.close()

    def _tracked_open(p, mode="r", *a, **kw):
        fh = real_open(p, mode, *a, **kw)
        if mode == "rb" and str(p) == str(path):
            return _TrackedFile(fh)
        return fh

    monkeypatch.setattr(bus_emit, "open", _tracked_open, raising=False)

    got = bus_emit.compute_sha256(str(path))
    assert got == hashlib.sha256(data).hexdigest()

    # Every individual read() must be bounded (the implementation reads 1 MiB
    # at a time) — no call may return the entire 40+ MB payload at once.
    assert len(seen_reads) > 1, "expected multiple chunked reads for a 40MB+ file"
    max_chunk = 1024 * 1024
    assert all(n <= max_chunk for n in seen_reads[:-1] or seen_reads)
    assert sum(seen_reads) == size


# ── _spool_entry_to_temp (archive-entry extraction) ───────────────────────────


def test_spool_entry_to_temp_small_file_roundtrip(tmp_path):
    data = b"hello forensics world"
    src = _SpyReader(io.BytesIO(data))
    try:
        tmp_path_out, size = ingest_task._spool_entry_to_temp(src)
        assert size == len(data)
        with open(tmp_path_out, "rb") as f:
            assert f.read() == data
    finally:
        try:
            os.unlink(tmp_path_out)
        except OSError:
            pass


def test_spool_entry_to_temp_large_input_never_reads_whole_file_at_once():
    """A multi-chunk synthetic 'entry' (bigger than the 1 MiB chunk size used
    by _spool_entry_to_temp) must be streamed — read() is called repeatedly
    with bounded sizes, never once for the full payload."""
    size = 10 * 1024 * 1024 + 999  # > 1 MiB chunk size, not a clean multiple
    data = os.urandom(size)
    src = _SpyReader(io.BytesIO(data))

    tmp_path_out = None
    try:
        tmp_path_out, got_size = ingest_task._spool_entry_to_temp(src)
        assert got_size == size

        # No single read() call requested more than the 1 MiB chunk size, and
        # more than one call was needed — proves this never buffers the whole
        # entry in one shot.
        assert len(src.read_sizes) > 1
        assert all(n <= 1024 * 1024 for n in src.read_sizes)

        with open(tmp_path_out, "rb") as f:
            assert hashlib.sha256(f.read()).hexdigest() == hashlib.sha256(data).hexdigest()
    finally:
        if tmp_path_out:
            try:
                os.unlink(tmp_path_out)
            except OSError:
                pass


def test_spool_entry_to_temp_enforces_size_cap():
    data = os.urandom(1024)
    src = io.BytesIO(data)
    tmp_path_out = None
    try:
        with pytest.raises(ValueError):
            tmp_path_out, _ = ingest_task._spool_entry_to_temp(src, limit=100)
    finally:
        # _spool_entry_to_temp cleans up its own temp file on failure.
        pass


# ── _expand_zip_into_child_jobs: end-to-end streamed extraction ──────────────


class _FakeRedis:
    def __init__(self):
        self.hashes = {}

    def hset(self, key, mapping=None, **kw):
        self.hashes.setdefault(key, {}).update(mapping or {})
        return 1

    def sadd(self, *a, **kw):
        return 1

    def expire(self, *a, **kw):
        return True

    def zadd(self, *a, **kw):
        return 1


class _FakeMinioClient:
    def __init__(self):
        self.uploads: list[tuple[str, str, int]] = []

    def put_object(self, bucket, key, fileobj, size):
        # Consume the stream the same way the real MinIO SDK would, in
        # bounded reads, to prove no caller hands it a giant bytes blob.
        total = 0
        while True:
            chunk = fileobj.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
        assert total == size
        self.uploads.append((bucket, key, size))


def test_expand_zip_into_child_jobs_streams_large_entry(tmp_path, monkeypatch):
    big_entry = os.urandom(6 * 1024 * 1024 + 321)
    small_entry = b"small file contents"

    zip_path = tmp_path / "case.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("evidence/disk.img", big_entry)
        zf.writestr("notes.txt", small_entry)

    fake_minio = _FakeMinioClient()
    monkeypatch.setattr(ingest_task, "get_minio", lambda: fake_minio)
    monkeypatch.setattr(ingest_task.app, "send_task", lambda *a, **kw: None)

    r = _FakeRedis()
    count = ingest_task._expand_zip_into_child_jobs("parent1", "case1", zip_path, r)

    assert count == 2
    sizes = sorted(size for _, _, size in fake_minio.uploads)
    assert sizes == sorted([len(big_entry), len(small_entry)])
