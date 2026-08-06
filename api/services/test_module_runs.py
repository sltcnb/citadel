"""Unit tests for module run bookkeeping in services/module_runs.py.

Covers the two things analysts notice when a case accumulates runs:
  * deleting a run really removes it from every index it was in, and
  * the list stays in launch order even for runs that never started
    (dispatch failures have no started_at at all).
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import redis_keys as rk  # noqa: E402

import services.module_runs as mr  # noqa: E402


@pytest.fixture
def fake(monkeypatch):
    client = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(mr, "get_redis", lambda: client)
    return client


def test_create_stamps_created_at(fake):
    run = mr.create_module_run("r1", "case1", "yara", [{"filename": "a.exe"}])
    assert run["created_at"]
    assert mr.get_module_run("r1")["created_at"] == run["created_at"]


def test_delete_removes_run_from_every_index(fake):
    mr.create_module_run("r1", "case1", "yara", [])
    fake.rpush(rk.module_log("r1"), "some log line")
    fake.set(rk.module_cancel("r1"), "1")

    mr.delete_module_run("r1", "case1")

    assert mr.get_module_run("r1") is None
    assert not fake.exists(rk.module_log("r1"))
    assert not fake.exists(rk.module_cancel("r1"))
    assert fake.smembers(rk.case_module_runs("case1")) == set()
    assert mr.list_case_module_runs("case1") == []


def test_delete_removes_standalone_run_from_malware_index(fake):
    mr.create_module_run("m1", mr.MALWARE_CASE_ID, "cuckoo", [])
    assert fake.zscore(rk.MALWARE_RUNS, "m1") is not None

    mr.delete_module_run("m1", mr.MALWARE_CASE_ID)

    assert fake.zscore(rk.MALWARE_RUNS, "m1") is None
    assert mr.list_malware_runs() == []


def test_delete_leaves_sibling_runs_alone(fake):
    mr.create_module_run("r1", "case1", "yara", [])
    mr.create_module_run("r2", "case1", "hayabusa", [])

    mr.delete_module_run("r1", "case1")

    assert [r["run_id"] for r in mr.list_case_module_runs("case1")] == ["r2"]


def test_never_started_runs_still_sort_newest_first(fake):
    """A run that failed at dispatch has started_at == "" — it used to fall back
    to sorting by the random run_id hex, so failures shuffled into arbitrary
    positions. created_at keeps them in launch order."""
    for rid, created in (("aaa", "2026-07-28T10:00:00+00:00"), ("zzz", "2026-07-28T09:00:00+00:00")):
        mr.create_module_run(rid, "case1", "cuckoo", [])
        mr.update_module_run(rid, created_at=created, status="FAILED", error="dispatch failed")

    assert [r["run_id"] for r in mr.list_case_module_runs("case1")] == ["aaa", "zzz"]


def test_retry_reset_keeps_created_at(fake):
    mr.create_module_run("r1", "case1", "yara", [])
    created = mr.get_module_run("r1")["created_at"]
    mr.update_module_run("r1", status="FAILED", started_at="2026-07-28T10:00:00+00:00")

    mr.reset_module_run_for_retry("r1")

    run = mr.get_module_run("r1")
    assert run["created_at"] == created
    assert run["started_at"] == ""
    assert run["status"] == "PENDING"


# ── Run params persistence (retry re-dispatches the run as launched) ──────────


def test_params_round_trip(fake):
    params = {"custom_rules": "rule x { condition: true }", "timeout_minutes": 15}
    mr.create_module_run("r1", "case1", "cuckoo", [], params=params)
    assert mr.get_module_run("r1")["params"] == params


def test_params_default_to_empty_dict(fake):
    mr.create_module_run("r1", "case1", "yara", [])
    assert mr.get_module_run("r1")["params"] == {}


def test_params_survive_retry_reset(fake):
    """The retry path re-dispatches run['params'] — the reset must not wipe them."""
    params = {"priority": 3, "timeout_minutes": 30}
    mr.create_module_run("r1", "case1", "cuckoo", [], params=params)
    mr.update_module_run("r1", status="FAILED", error="boom")

    mr.reset_module_run_for_retry("r1")

    run = mr.get_module_run("r1")
    assert run["status"] == "PENDING"
    assert run["params"] == params


# ── Stale-run reaper (worker died mid-run / queue message lost) ───────────────


def _iso_ago(seconds: float) -> str:
    return (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat()


def test_reaper_fails_stale_running_run(fake):
    mr.create_module_run("r1", "case1", "yara", [])
    mr.update_module_run(
        "r1", status="RUNNING", started_at=_iso_ago(mr.STALE_RUN_SECONDS + 60)
    )

    run = mr.get_module_run("r1")

    assert run["status"] == "FAILED"
    assert run["error"] == mr.STALE_RUN_ERROR
    assert run["completed_at"]
    # Persisted — a second read is FAILED without re-reaping.
    assert mr.get_module_run("r1")["status"] == "FAILED"


def test_reaper_leaves_fresh_running_run_alone(fake):
    mr.create_module_run("r1", "case1", "yara", [])
    mr.update_module_run("r1", status="RUNNING", started_at=_iso_ago(60))

    run = mr.get_module_run("r1")

    assert run["status"] == "RUNNING"
    assert run["error"] == ""


def test_reaper_fails_stale_pending_run(fake):
    """A PENDING run whose queue message was lost never gets a started_at —
    staleness is measured from created_at."""
    mr.create_module_run("r1", "case1", "yara", [])
    mr.update_module_run("r1", created_at=_iso_ago(mr.STALE_RUN_SECONDS + 60))

    run = mr.get_module_run("r1")

    assert run["status"] == "FAILED"
    assert run["error"] == mr.STALE_RUN_ERROR


def test_reaper_leaves_fresh_pending_run_alone(fake):
    mr.create_module_run("r1", "case1", "yara", [])

    run = mr.get_module_run("r1")

    assert run["status"] == "PENDING"
    assert run["error"] == ""


def test_reaper_ignores_terminal_runs(fake):
    mr.create_module_run("r1", "case1", "yara", [])
    mr.update_module_run(
        "r1",
        status="COMPLETED",
        started_at=_iso_ago(mr.STALE_RUN_SECONDS + 3600),
        completed_at=_iso_ago(mr.STALE_RUN_SECONDS + 60),
    )

    assert mr.get_module_run("r1")["status"] == "COMPLETED"


def test_reaper_sweeps_during_case_list(fake):
    """The UI polls list_case_module_runs — the sweep must self-heal there."""
    mr.create_module_run("stale", "case1", "yara", [])
    mr.update_module_run(
        "stale", status="RUNNING", started_at=_iso_ago(mr.STALE_RUN_SECONDS + 60)
    )
    mr.create_module_run("fresh", "case1", "yara", [])
    mr.update_module_run("fresh", status="RUNNING", started_at=_iso_ago(60))

    runs = {r["run_id"]: r for r in mr.list_case_module_runs("case1")}

    assert runs["stale"]["status"] == "FAILED"
    assert runs["stale"]["error"] == mr.STALE_RUN_ERROR
    assert runs["fresh"]["status"] == "RUNNING"
