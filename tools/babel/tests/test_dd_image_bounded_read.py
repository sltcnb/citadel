"""The dd-image S3 reader must never slurp an image unboundedly.

``S3RangeReader.read(-1)`` ("read all remaining") is the dangerous path: a naive
implementation would materialise a multi-GB disk image in RAM in a single call.
The hardened version caps a single ``read(-1)`` to ``_MAX_READ_ALL`` bytes and
expects callers to loop until it returns ``b""``.

These tests use a fake MinIO client (no network, no pytsk3) that honours the
``offset``/``length`` Range-GET arguments, and assert that no single call ever
returns — or even requests — more than the bound.
"""

from __future__ import annotations

from babel.dd_image import dd_image_plugin as dd
from babel.dd_image.dd_image_plugin import S3RangeReader


class _FakeResp:
    def __init__(self, data: bytes):
        self._data = data

    def read(self):
        return self._data

    def close(self):
        pass

    def release_conn(self):
        pass


class _FakeStat:
    def __init__(self, size: int):
        self.size = size


class _FakeMinio:
    """Records every Range-GET so tests can assert the requested lengths."""

    def __init__(self, size: int):
        self._size = size
        self.requests: list[tuple[int, int]] = []

    def stat_object(self, bucket, key):
        return _FakeStat(self._size)

    def get_object(self, bucket, key, offset=0, length=None):
        self.requests.append((offset, length))
        end = offset + (length if length is not None else self._size - offset)
        return _FakeResp(b"\x00" * (end - offset))


def test_read_all_is_bounded_per_call(monkeypatch):
    # Tiny bound so the test is fast; image is many multiples of it.
    monkeypatch.setattr(dd, "_MAX_READ_ALL", 1024)
    total = 1024 * 10 + 7  # not a clean multiple, to exercise the tail
    client = _FakeMinio(total)

    reader = S3RangeReader(client, "bucket", "disk.dd")

    # First read(-1) must be capped, not the whole object.
    first = reader.read(-1)
    assert len(first) == dd._MAX_READ_ALL
    # It requested exactly the bounded length from S3 — never the full image.
    assert client.requests[-1][1] == dd._MAX_READ_ALL

    # Draining via the loop contract yields the whole object, but never more
    # than the bound in any single call/request.
    got = len(first)
    calls = 1
    while True:
        chunk = reader.read(-1)
        if not chunk:
            break
        calls += 1
        assert len(chunk) <= dd._MAX_READ_ALL
        got += len(chunk)

    assert got == total
    assert calls >= total // dd._MAX_READ_ALL
    assert all(
        (length is None or length <= dd._MAX_READ_ALL) for _, length in client.requests
    )


def test_positive_read_is_clamped_to_remaining(monkeypatch):
    monkeypatch.setattr(dd, "_MAX_READ_ALL", 1_000_000)
    client = _FakeMinio(100)
    reader = S3RangeReader(client, "bucket", "disk.dd")

    reader.seek(90)
    # Asking for more than remains never over-reads past EOF.
    chunk = reader.read(4096)
    assert len(chunk) == 10
    assert reader.read(1) == b""  # at EOF


def test_read_all_does_not_request_whole_large_image(monkeypatch):
    # Regression guard: a huge image must not trigger a single giant Range-GET.
    monkeypatch.setattr(dd, "_MAX_READ_ALL", 64 * 1024 * 1024)
    huge = 500 * 1024 * 1024 * 1024  # 500 GiB
    client = _FakeMinio(huge)
    reader = S3RangeReader(client, "bucket", "disk.dd")

    reader.read(-1)
    offset, length = client.requests[-1]
    assert length == dd._MAX_READ_ALL
    assert length < huge
