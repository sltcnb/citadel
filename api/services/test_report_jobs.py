"""Unit tests for the AI report generation job store (services/report_jobs.py)."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import services.report_jobs as rj  # noqa: E402


@pytest.fixture
def fake(monkeypatch):
    client = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(rj, "get_redis", lambda: client)
    return client


def _wait_done(case_id: str, timeout: float = 5.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = rj.get_job(case_id)
        if job and job["status"] in ("done", "error"):
            return job
        time.sleep(0.01)
    raise AssertionError("job did not finish in time")


def test_successful_job_stores_result(fake):
    assert rj.start_job("c1", lambda: {"content": "report"})
    job = _wait_done("c1")
    assert job["status"] == "done"
    assert job["result"] == {"content": "report"}
    assert job["started_at"] and job["finished_at"]
    assert job["error"] is None
    assert fake.ttl(rj._key("c1")) > 0  # 24h TTL is set


def test_failing_job_stores_error(fake):
    def boom():
        raise RuntimeError("LLM call failed")

    assert rj.start_job("c1", boom)
    job = _wait_done("c1")
    assert job["status"] == "error"
    assert "LLM call failed" in job["error"]
    assert job["result"] is None


def test_second_start_while_active_is_refused(fake):
    gate = threading.Event()

    def slow():
        gate.wait(2)

    assert rj.start_job("c1", slow)
    try:
        # "pending" is stored synchronously, so the duplicate is refused even
        # before the worker thread gets scheduled.
        assert not rj.start_job("c1", lambda: {"content": "other"})
    finally:
        gate.set()
    assert _wait_done("c1")["status"] == "done"


def test_restart_after_completion_allowed(fake):
    assert rj.start_job("c1", lambda: {"content": "v1"})
    _wait_done("c1")
    assert rj.start_job("c1", lambda: {"content": "v2"})
    assert _wait_done("c1")["result"] == {"content": "v2"}


def test_unknown_case_has_no_job(fake):
    assert rj.get_job("nope") is None
