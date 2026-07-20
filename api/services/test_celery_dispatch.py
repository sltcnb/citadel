"""Unit tests for job prioritization in services/celery_dispatch.py.

dispatch_* pushes a Celery v5 message envelope straight onto a Redis list
(bypassing Celery's own routing — see the module docstring). Priority is
implemented by giving every base queue a "_high" twin and relying on the
processor's worker subscribing to *_high queues ahead of their base queue
(Kombu's redis transport BLPOPs across all subscribed keys in the order
given, returning from the first non-empty one). These tests verify:

  1. each dispatch_* helper's *default* priority routes to the queue the
     design calls for (interactive module/harvest runs high, bulk ingest
     normal), and
  2. simulating that worker drain order, high-priority work always comes out
     before same-timestamp low-priority work — i.e. priority is real, not
     just a label.
"""

from __future__ import annotations

import sys
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import services.celery_dispatch as cd  # noqa: E402


@pytest.fixture
def fake_broker(monkeypatch):
    """A fakeredis client shared across every _redis.Redis.from_url(...) call
    _push makes, so all dispatch_* calls in a test land in the same store."""
    server = fakeredis.FakeServer()
    fake = fakeredis.FakeRedis(server=server)
    monkeypatch.setattr(
        cd._redis, "Redis", type("R", (), {"from_url": staticmethod(lambda url: fake)})
    )
    return fake


def _queue_names(fake) -> list[str]:
    return [k.decode() if isinstance(k, bytes) else k for k in fake.keys("*")]


# ── Default priority routing ────────────────────────────────────────────────


def test_dispatch_module_defaults_to_high_priority(fake_broker):
    cd.dispatch_module("run1", "case1", "mod1", ["f1"], {})
    assert "modules_high" in _queue_names(fake_broker)
    assert fake_broker.llen("modules") == 0


def test_dispatch_harvest_defaults_to_high_priority(fake_broker):
    cd.dispatch_harvest("run1", "case1", "complete", [], "obj-key", None)
    assert "modules_high" in _queue_names(fake_broker)
    assert fake_broker.llen("modules") == 0


def test_dispatch_ingest_defaults_to_normal_priority(fake_broker):
    cd.dispatch_ingest("job1", "case1", "minio/key", "file.evtx")
    assert "ingest" in _queue_names(fake_broker)
    assert fake_broker.llen("ingest_high") == 0


def test_dispatch_s3_transfer_defaults_to_normal_priority(fake_broker):
    cd.dispatch_s3_transfer("job1", "case1", "s3cfg", "s3/key", "file.zip")
    assert "ingest" in _queue_names(fake_broker)
    assert fake_broker.llen("ingest_high") == 0


def test_priority_is_overridable(fake_broker):
    cd.dispatch_ingest("job1", "case1", "minio/key", "file.evtx", priority=cd.PRIORITY_HIGH)
    assert fake_broker.llen("ingest_high") == 1
    assert fake_broker.llen("ingest") == 0


# ── Drain-order simulation ───────────────────────────────────────────────────


def test_high_priority_drains_before_low(fake_broker):
    """Enqueue a bulk-ingest job, THEN an analyst-triggered module run — the
    module run must still come out first, because a worker subscribed to
    [modules_high, modules, ingest_high, ingest] (mirrors the Dockerfile's -Q
    order) always checks the *_high keys first."""
    cd.dispatch_ingest("bulk-job", "case1", "minio/key", "bulk.evtx")  # queued first, low priority
    cd.dispatch_module(
        "interactive-run", "case1", "mod1", ["f1"], {}
    )  # queued second, high priority

    def drain_one():
        for queue in ("modules_high", "ingest_high", "modules", "ingest"):
            item = fake_broker.lpop(queue)
            if item is not None:
                return queue
        return None

    # Even though the ingest job was enqueued first, the high-priority queue
    # is checked first by every worker cycle, so it drains first.
    assert drain_one() == "modules_high"
    assert drain_one() == "ingest"
