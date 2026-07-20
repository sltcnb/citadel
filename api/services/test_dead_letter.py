"""Unit tests for dead-letter list/replay in services/dead_letter.py."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import services.celery_dispatch as cd  # noqa: E402
import services.dead_letter as dl  # noqa: E402


@pytest.fixture
def fake(monkeypatch):
    """A single fakeredis instance backing both config.get_redis() (used by
    dead_letter.py) and _redis.Redis.from_url() (used by celery_dispatch's
    _push when a replay re-enqueues)."""
    server = fakeredis.FakeServer()
    client = fakeredis.FakeRedis(server=server, decode_responses=True)

    monkeypatch.setattr(dl, "get_redis", lambda: client)
    # celery_dispatch decodes nothing (raw bytes client) internally but only
    # ever calls rpush/hset-free ops here, so a decode_responses client is fine.
    monkeypatch.setattr(
        cd._redis, "Redis", type("R", (), {"from_url": staticmethod(lambda url: client)})
    )
    return client


def _seed_dead_letter(fake, *, task="ingest.process_artifact", job_id="j1", task_id="t1"):
    entry = {
        "task": task,
        "task_id": task_id,
        "args": [job_id, "case1", "cases/case1/j1/x.evtx", "x.evtx"],
        "error": "boom",
        "retries": 3,
        "failed_at": "2026-01-01T00:00:00+00:00",
    }
    fake.lpush(dl.DEAD_LETTER_KEY, json.dumps(entry))
    return entry


def test_list_dead_letters_newest_first(fake):
    _seed_dead_letter(fake, job_id="j1", task_id="t1")
    _seed_dead_letter(fake, job_id="j2", task_id="t2")
    entries = dl.list_dead_letters()
    assert [e["task_id"] for e in entries] == ["t2", "t1"]
    assert entries[0]["index"] == 0


def test_replay_reenqueues_and_clears_entry(fake):
    _seed_dead_letter(fake, job_id="j1", task_id="t1")
    assert dl.dead_letter_count() == 1

    result = dl.replay_entry(0)

    assert result["status"] == "requeued"
    assert result["job_id"] == "j1"
    assert result["queue"] == "ingest"
    # Cleared from the dead-letter list.
    assert dl.dead_letter_count() == 0
    # Re-enqueued onto the high-priority twin of its queue (replays jump the
    # queue since an operator explicitly asked for them).
    assert fake.llen("ingest_high") == 1
    assert fake.llen("ingest") == 0


def test_replay_is_idempotent_when_job_already_succeeded(fake):
    _seed_dead_letter(fake, job_id="j1", task_id="t1")
    fake.hset("job:j1", mapping={"status": "COMPLETED"})

    result = dl.replay_entry(0)

    assert result["status"] == "skipped_already_processed"
    # Still cleared — a stale dead-letter entry for done work shouldn't linger.
    assert dl.dead_letter_count() == 0
    # And, crucially, nothing was re-enqueued.
    assert fake.llen("ingest_high") == 0
    assert fake.llen("ingest") == 0


def test_replay_missing_index_raises_keyerror(fake):
    with pytest.raises(KeyError):
        dl.replay_entry(0)


def test_replay_all_drains_every_entry(fake):
    _seed_dead_letter(fake, job_id="j1", task_id="t1")
    _seed_dead_letter(fake, job_id="j2", task_id="t2")
    fake.hset("job:j2", mapping={"status": "COMPLETED"})  # already done → skipped

    summary_results = dl.replay_all()

    assert dl.dead_letter_count() == 0
    statuses = {r["job_id"]: r["status"] for r in summary_results}
    assert statuses["j1"] == "requeued"
    assert statuses["j2"] == "skipped_already_processed"
    assert fake.llen("ingest_high") == 1  # only j1 got re-enqueued
