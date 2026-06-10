"""In-memory enrichment cache with TTL.

Keyed by ``(source, ioc_type, normalized_value)``. The same interface could be
backed by Redis (the brick.yaml dependency) without touching callers.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from .models import IOC, SourceVerdict

CacheKey = tuple[str, str, str]


class TTLCache:
    """Thread-safe in-memory cache with per-entry expiry."""

    def __init__(self, ttl_seconds: float = 3600.0) -> None:
        self.ttl = float(ttl_seconds)
        self._store: dict[CacheKey, tuple[float, Any]] = {}
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    @staticmethod
    def key(source: str, ioc: IOC) -> CacheKey:
        return (source, ioc.type.value, ioc.normalized)

    def get(self, key: CacheKey, *, now: float | None = None) -> SourceVerdict | None:
        now = time.monotonic() if now is None else now
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self.misses += 1
                return None
            expires_at, value = entry
            if now >= expires_at:
                del self._store[key]
                self.misses += 1
                return None
            self.hits += 1
            return value

    def set(self, key: CacheKey, value: SourceVerdict, *, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            self._store[key] = (now + self.ttl, value)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)
