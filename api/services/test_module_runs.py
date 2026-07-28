"""Unit tests for module run bookkeeping in services/module_runs.py.

Covers the two things analysts notice when a case accumulates runs:
  * deleting a run really removes it from every index it was in, and
  * the list stays in launch order even for runs that never started
    (dispatch failures have no started_at at all).
"""

from __future__ import annotations

import sys
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
