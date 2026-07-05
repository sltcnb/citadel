"""Test fixtures for the processor (Sluice async stages).

Adds the processor package root to sys.path so `import bus_emit` works when
pytest is invoked from the repo root, and provides a tiny in-memory fake Redis
that implements only the surface bus_emit uses (sadd/srem/expire/xadd/xrange).
This keeps the unit tests dependency-free — no real redis-py / redis server.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PROCESSOR_ROOT = Path(__file__).resolve().parent.parent
if str(_PROCESSOR_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROCESSOR_ROOT))


class FakeRedis:
    """Minimal in-memory stand-in for redis.Redis (only what bus_emit touches)."""

    def __init__(self) -> None:
        self.sets: dict[str, set] = {}
        self.streams: dict[str, list[tuple[str, dict]]] = {}
        self.expires: dict[str, int] = {}
        self._seq = 0

    # ── set ops (used by the dedup logic) ──────────────────────────────────
    def sadd(self, key: str, *members) -> int:
        s = self.sets.setdefault(key, set())
        added = 0
        for m in members:
            if m not in s:
                s.add(m)
                added += 1
        return added

    def srem(self, key: str, *members) -> int:
        s = self.sets.get(key, set())
        removed = 0
        for m in members:
            if m in s:
                s.discard(m)
                removed += 1
        return removed

    def sismember(self, key: str, member) -> bool:
        return member in self.sets.get(key, set())

    def expire(self, key: str, ttl: int) -> bool:
        self.expires[key] = ttl
        return True

    # ── stream ops (used by the bus emit) ──────────────────────────────────
    def xadd(self, stream: str, fields: dict) -> str:
        self._seq += 1
        entry_id = f"0-{self._seq}"
        self.streams.setdefault(stream, []).append((entry_id, dict(fields)))
        return entry_id

    def xrange(self, stream: str):
        return list(self.streams.get(stream, []))

    def xlen(self, stream: str) -> int:
        return len(self.streams.get(stream, []))


@pytest.fixture
def fake_redis() -> FakeRedis:
    return FakeRedis()
