"""Cooperative cancel for the harvest task (tasks/harvest_task.py).

The DELETE /harvest/runs/{run_id} endpoint sets a Redis flag
(rk.harvest_cancel) and marks the run CANCELLED. The worker must:
  * honour the flag at category boundaries and stop with status CANCELLED,
    clearing the flag;
  * honour it when set while the task was still queued;
  * never clobber a terminal CANCELLED status with COMPLETED at the end.

Runs against an in-memory fake Redis + a stubbed filesystem accessor — no
Celery broker, MinIO, or pytsk3 needed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("celery")

_WORKER_ROOT = Path(__file__).resolve().parents[1]
_TASKS_DIR = _WORKER_ROOT / "tasks"

for _p in (str(_WORKER_ROOT), str(_TASKS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import harvest_task as ht
    import redis_keys as rk
except ModuleNotFoundError:
    pytest.skip("harvest_task's hard dependency chain is unavailable", allow_module_level=True)


class _FakeRedis:
    """In-memory subset of redis.Redis used by harvest_task."""

    def __init__(self) -> None:
        self.hashes: dict[str, dict] = {}
        self.kv: dict[str, str] = {}
        self.expires: dict[str, int] = {}

    def hset(self, key, field=None, value=None, mapping=None):
        h = self.hashes.setdefault(key, {})
        if mapping:
            h.update({k: str(v) for k, v in mapping.items()})
        if field is not None:
            h[field] = value
        return 1

    def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def get(self, key):
        return self.kv.get(key)

    def set(self, key, value, **kw):
        self.kv[key] = value
        return True

    def delete(self, *keys):
        for k in keys:
            self.kv.pop(k, None)
            self.hashes.pop(k, None)
        return len(keys)

    def expire(self, key, ttl):
        self.expires[key] = ttl
        return True


class _FakeFs:
    """Empty filesystem — nothing to collect, so no MinIO/dispatch is needed."""

    def close(self):
        pass


@pytest.fixture
def env(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(ht, "_get_redis", lambda: fake)
    monkeypatch.setattr(ht, "_get_minio", lambda: object())
    monkeypatch.setattr(ht._FsAccess, "open_auto", staticmethod(lambda source: _FakeFs()))
    return fake


def _run_key(run_id: str) -> str:
    return f"harvest_run:{run_id}"


def test_cancel_flag_set_while_queued_stops_immediately(env):
    run_id = "run-queued"
    env.set(rk.harvest_cancel(run_id), "1")

    result = ht.run_harvest(run_id, "case-1", level="small", mounted_path="/mnt/fake")

    assert result["status"] == "CANCELLED"
    assert env.hget(_run_key(run_id), "status") == "CANCELLED"
    # Flag consumed — a stale flag must not kill a future run with the same id.
    assert env.get(rk.harvest_cancel(run_id)) is None


def test_cancel_flag_honoured_at_category_boundary(env, monkeypatch):
    run_id = "run-midrun"
    collected = []

    def _spy_collect(fs, cat, cat_def, level, work_dir, minio, r, case_id, rid):
        collected.append(cat)
        # Analyst hits cancel after the first category completes.
        r.set(rk.harvest_cancel(rid), "1")
        return 0

    monkeypatch.setattr(ht, "_collect_category", _spy_collect)

    result = ht.run_harvest(run_id, "case-1", level="small", mounted_path="/mnt/fake")

    assert result["status"] == "CANCELLED"
    assert env.hget(_run_key(run_id), "status") == "CANCELLED"
    assert env.get(rk.harvest_cancel(run_id)) is None
    # Stopped at the next boundary — only the first category was collected.
    assert len(collected) == 1


def test_completed_run_writes_completed_status(env):
    run_id = "run-ok"
    result = ht.run_harvest(run_id, "case-1", level="small", mounted_path="/mnt/fake")
    assert result["status"] == "COMPLETED"
    assert env.hget(_run_key(run_id), "status") == "COMPLETED"


def test_terminal_cancelled_status_is_not_clobbered(env, monkeypatch):
    """Race: the API marks the run CANCELLED after the worker's last category
    check but before the final write — the end-of-run update must not turn it
    back into COMPLETED."""
    run_id = "run-race"

    real_update = ht._update_run

    def _racing_update(r, rid, **fields):
        real_update(r, rid, **fields)
        # As soon as the last category boundary passed (categories written),
        # simulate the API-side cancel: flag consumed elsewhere, status set.
        if "categories" in fields:
            r.hset(_run_key(rid), mapping={"status": "CANCELLED"})

    monkeypatch.setattr(ht, "_update_run", _racing_update)

    result = ht.run_harvest(run_id, "case-1", level="small", mounted_path="/mnt/fake")

    assert result["status"] == "CANCELLED"
    assert env.hget(_run_key(run_id), "status") == "CANCELLED"


def test_level_category_lists_reference_only_known_categories():
    for level, cats in ht.LEVEL_CATEGORIES.items():
        unknown = [c for c in cats if c not in ht.HARVEST_CATEGORIES]
        assert not unknown, f"level {level!r} references unknown categories: {unknown}"
