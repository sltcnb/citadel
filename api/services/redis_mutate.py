"""Atomic read-modify-write for Redis JSON values (optimistic locking)."""
from __future__ import annotations
import json
from redis import WatchError

def mutate_json(r, key, fn, default, retries=25):
    """Atomically read key, apply fn(value)->new_value, write back.
    Retries on concurrent modification (WATCH/MULTI). `default` is the parsed
    value used when the key is absent (pass [] or {}). Returns the new value."""
    for _ in range(retries):
        with r.pipeline() as pipe:
            try:
                pipe.watch(key)
                raw = pipe.get(key)
                cur = json.loads(raw) if raw else (default.copy() if hasattr(default, "copy") else default)
                new = fn(cur)
                pipe.multi()
                pipe.set(key, json.dumps(new))
                pipe.execute()
                return new
            except WatchError:
                continue
    raise RuntimeError(f"Redis contention on {key} after {retries} retries")
