"""Unit tests for the MinIO storage layer's typed errors and integrity checks.

The real Minio client is mocked via ``storage.get_minio`` so no live MinIO is
required.
"""

import hashlib
import io
from datetime import UTC, datetime

import pytest

from services import storage


class _FakeS3Error(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class _FakeStat:
    def __init__(self, size, etag="abc", ct="text/plain"):
        self.size = size
        self.etag = etag
        self.last_modified = datetime.now(UTC)
        self.content_type = ct


class _FakeResp:
    def __init__(self, data):
        self._data = data
        self.closed = False

    def read(self):
        return self._data

    def stream(self, n):
        for i in range(0, len(self._data), n):
            yield self._data[i : i + n]

    def close(self):
        self.closed = True

    def release_conn(self):
        pass


class _FakeMinio:
    def __init__(self, objects=None, raise_on_get=None):
        self.objects = objects or {}
        self.raise_on_get = raise_on_get
        self.removed = []

    def stat_object(self, bucket, key):
        if key not in self.objects:
            raise _FakeS3Error("NoSuchKey")
        return _FakeStat(len(self.objects[key]))

    def get_object(self, bucket, key):
        if self.raise_on_get:
            raise self.raise_on_get
        if key not in self.objects:
            raise _FakeS3Error("NoSuchKey")
        return _FakeResp(self.objects[key])

    def remove_object(self, bucket, key):
        self.removed.append(key)


@pytest.fixture(autouse=True)
def _patch_s3error(monkeypatch):
    """Make storage's ``from minio.error import S3Error`` resolve to our fake."""
    import sys
    import types

    fake_mod = types.ModuleType("minio.error")
    fake_mod.S3Error = _FakeS3Error
    monkeypatch.setitem(sys.modules, "minio.error", fake_mod)


def _use(monkeypatch, client):
    monkeypatch.setattr(storage, "get_minio", lambda: client)


def test_stat_object_returns_metadata(monkeypatch):
    _use(monkeypatch, _FakeMinio({"cases/c1/f": b"hello"}))
    st = storage.stat_object("cases/c1/f")
    assert st.size == 5
    assert st.object_key == "cases/c1/f"


def test_stat_object_missing_raises_objectnotfound(monkeypatch):
    _use(monkeypatch, _FakeMinio({}))
    with pytest.raises(storage.ObjectNotFound):
        storage.stat_object("cases/c1/missing")


def test_download_missing_raises_objectnotfound(monkeypatch):
    _use(monkeypatch, _FakeMinio({}))
    with pytest.raises(storage.ObjectNotFound):
        storage.download_fileobj("cases/c1/missing")


def test_download_returns_bytes_and_closes(monkeypatch):
    client = _FakeMinio({"cases/c1/f": b"payload"})
    _use(monkeypatch, client)
    assert storage.download_fileobj("cases/c1/f") == b"payload"


def test_download_transient_raises_storageunavailable(monkeypatch):
    client = _FakeMinio(raise_on_get=Exception("Connection refused"))
    _use(monkeypatch, client)
    with pytest.raises(storage.StorageUnavailable):
        storage.download_fileobj("cases/c1/f")


def test_download_sha256_mismatch_raises_integrity(monkeypatch):
    _use(monkeypatch, _FakeMinio({"cases/c1/f": b"payload"}))
    with pytest.raises(storage.IntegrityError):
        storage.download_fileobj("cases/c1/f", expected_sha256="deadbeef")


def test_download_size_mismatch_raises_integrity(monkeypatch):
    _use(monkeypatch, _FakeMinio({"cases/c1/f": b"payload"}))
    with pytest.raises(storage.IntegrityError):
        storage.download_fileobj("cases/c1/f", expected_size=999)


def test_download_correct_hash_passes(monkeypatch):
    data = b"payload"
    _use(monkeypatch, _FakeMinio({"cases/c1/f": data}))
    good = hashlib.sha256(data).hexdigest()
    assert storage.download_fileobj(
        "cases/c1/f", expected_size=len(data), expected_sha256=good
    ) == data


def test_stream_object_yields_chunks(monkeypatch):
    _use(monkeypatch, _FakeMinio({"cases/c1/f": b"abcdef"}))
    chunks = list(storage.stream_object("cases/c1/f", chunk_size=2))
    assert b"".join(chunks) == b"abcdef"


def test_stream_object_missing_raises(monkeypatch):
    _use(monkeypatch, _FakeMinio({}))
    with pytest.raises(storage.ObjectNotFound):
        list(storage.stream_object("cases/c1/missing"))


def test_object_exists_false_on_missing(monkeypatch):
    _use(monkeypatch, _FakeMinio({}))
    assert storage.object_exists("cases/c1/missing") is False


def test_object_exists_true(monkeypatch):
    _use(monkeypatch, _FakeMinio({"cases/c1/f": b"x"}))
    assert storage.object_exists("cases/c1/f") is True


def test_compute_and_verify_sha256():
    data = b"hello world"
    digest = storage.compute_sha256(data)
    assert storage.verify_sha256(data, digest)
    assert storage.verify_sha256(data, digest.upper())
    assert not storage.verify_sha256(data, "0" * 64)
