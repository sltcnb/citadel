"""Unit tests for the worker robustness helpers: idempotency, dead-letter,
and backpressure. Uses the dependency-free FakeRedis from conftest."""

from __future__ import annotations

import json

import pytest

import robustness


# ── Idempotency ──────────────────────────────────────────────────────────────


def test_idempotency_terminal_status_is_noop(fake_redis):
    fake_redis.hset("job:j1", mapping={"status": "COMPLETED"})
    assert robustness.job_already_processed(fake_redis, "j1") is True
    fake_redis.hset("job:j2", mapping={"status": "SKIPPED"})
    assert robustness.job_already_processed(fake_redis, "j2") is True


def test_idempotency_non_terminal_allows_processing(fake_redis):
    for status in ("PENDING", "RUNNING", "FAILED", "CANCELLED"):
        fake_redis.hset("job:j", mapping={"status": status})
        assert robustness.job_already_processed(fake_redis, "j") is False
    # Unknown job → process it (fail open).
    assert robustness.job_already_processed(fake_redis, "missing") is False
    assert robustness.job_already_processed(fake_redis, "") is False


def test_double_process_yields_single_effect(fake_redis):
    """Simulate a redelivered task: the first run completes the job, the second
    run sees a terminal status and must be a no-op (one effect, not two)."""
    effects = []

    def process(job_id):
        if robustness.job_already_processed(fake_redis, job_id):
            return "noop"
        effects.append(job_id)  # the one real side effect
        fake_redis.hset(f"job:{job_id}", mapping={"status": "COMPLETED"})
        return "done"

    assert process("j1") == "done"
    assert process("j1") == "noop"
    assert effects == ["j1"]


# ── Dead-letter ──────────────────────────────────────────────────────────────


def test_retries_exhausted_boundary(monkeypatch):
    monkeypatch.setattr(robustness, "TASK_MAX_RETRIES", 3)
    assert robustness.retries_exhausted(0) is False
    assert robustness.retries_exhausted(2) is False
    assert robustness.retries_exhausted(3) is True
    assert robustness.retries_exhausted(4) is True


def test_dead_letter_after_max_retries(fake_redis, monkeypatch):
    monkeypatch.setattr(robustness, "TASK_MAX_RETRIES", 3)
    retries = 0
    # Poison task keeps failing; it retries until the budget is exhausted, then
    # is parked on the dead-letter list with the error captured.
    while not robustness.retries_exhausted(retries):
        retries += 1
    assert robustness.dead_letter_size(fake_redis) == 0
    entry = robustness.to_dead_letter(
        fake_redis,
        task_name="ingest.process_artifact",
        task_id="task-123",
        args=["j1", "c1", "cases/c1/j1/x.evtx", "x.evtx"],
        error=RuntimeError("boom"),
        retries=retries,
    )
    assert robustness.dead_letter_size(fake_redis) == 1
    assert entry["retries"] == 3
    stored = json.loads(fake_redis.lrange(robustness.DEAD_LETTER_KEY, 0, -1)[0])
    assert stored["task"] == "ingest.process_artifact"
    assert stored["error"] == "boom"
    assert stored["args"][0] == "j1"


def test_dead_letter_is_capped(fake_redis, monkeypatch):
    monkeypatch.setattr(robustness, "DEAD_LETTER_MAXLEN", 3)
    for i in range(10):
        robustness.to_dead_letter(
            fake_redis,
            task_name="t",
            task_id=str(i),
            args=[],
            error=f"e{i}",
            retries=3,
        )
    assert robustness.dead_letter_size(fake_redis) == 3


def test_retry_countdown_backoff(monkeypatch):
    monkeypatch.setattr(robustness, "TASK_RETRY_BACKOFF", 30)
    monkeypatch.setattr(robustness, "TASK_RETRY_BACKOFF_MAX", 600)
    assert robustness.retry_countdown(0) == 30
    assert robustness.retry_countdown(1) == 60
    assert robustness.retry_countdown(2) == 120
    assert robustness.retry_countdown(10) == 600  # capped


# ── Backpressure ─────────────────────────────────────────────────────────────


def test_backpressure_unbounded_by_default(fake_redis, monkeypatch):
    monkeypatch.setattr(robustness, "MAX_IN_FLIGHT", 0)
    for _ in range(100):
        assert robustness.acquire_slot(fake_redis) is True


def test_backpressure_bounds_in_flight(fake_redis, monkeypatch):
    monkeypatch.setattr(robustness, "MAX_IN_FLIGHT", 2)
    assert robustness.acquire_slot(fake_redis) is True   # 1
    assert robustness.acquire_slot(fake_redis) is True   # 2
    assert robustness.acquire_slot(fake_redis) is False  # over cap
    # Releasing a slot frees capacity again.
    robustness.release_slot(fake_redis)
    assert robustness.acquire_slot(fake_redis) is True
    # Counter never goes negative.
    for _ in range(5):
        robustness.release_slot(fake_redis)
    assert int(fake_redis.get(robustness._INFLIGHT_KEY)) >= 0
