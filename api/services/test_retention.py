"""Unit tests for the case retention lifecycle sweep (services.retention).

Redis is fakeredis; the archive/purge machinery (routers.export → MinIO/ES)
and the audit writer are stubbed — the tests exercise the DECISION logic:
who gets archived, who gets purged, who is skipped.
"""

from datetime import UTC, datetime, timedelta

import fakeredis
import pytest
import redis_keys as rk

from services import cases as case_svc
from services import jobs as job_svc
from services import retention

NOW = datetime.now(UTC)


def _iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


@pytest.fixture
def env(monkeypatch):
    """fakeredis wired into every module the sweep touches, plus stubs for the
    archive/purge machinery and the audit trail. Returns a namespace with the
    stubs so tests can assert on calls."""
    fake = fakeredis.FakeRedis(decode_responses=True)

    monkeypatch.setattr(retention, "get_redis", lambda: fake)
    monkeypatch.setattr(case_svc, "get_redis", lambda: fake)
    monkeypatch.setattr(job_svc, "get_redis", lambda: fake)

    calls = {"archive": [], "purge": [], "audit": []}

    def _fake_archive(case_id):
        calls["archive"].append(case_id)
        return {"ok": True, "archive_key": f"case_archive/{case_id}/case-{case_id}.citadel",
                "event_count": 0}

    def _fake_purge(case_id):
        calls["purge"].append(case_id)
        return {"ok": True}

    def _fake_audit(**kwargs):
        calls["audit"].append(kwargs)

    monkeypatch.setattr(retention, "_archive_case", _fake_archive)
    monkeypatch.setattr(retention, "_purge_case", _fake_purge)
    monkeypatch.setattr(retention.audit_svc, "record_event", _fake_audit)

    # Retention thresholds: archive after 30 idle days, purge 30 days later.
    monkeypatch.setattr(retention, "_retention_config", lambda: (30, 30))

    # Archive S3 configured (the sweep refuses to run without it).
    fake.set(rk.ARCHIVE_SETTINGS, '{"s3_endpoint": "minio:9000", "s3_bucket": "archives"}')

    return type("Env", (), {"redis": fake, "calls": calls})()


def _make_case(fake, case_id, status="active", updated_days_ago=60, **extra):
    mapping = {
        "case_id": case_id,
        "name": f"Case {case_id}",
        "status": status,
        "created_at": _iso(updated_days_ago + 10),
        "updated_at": _iso(updated_days_ago),
    }
    mapping.update(extra)
    fake.hset(f"case:{case_id}", mapping=mapping)
    fake.sadd("cases:all", case_id)


# ── Archive decisions ─────────────────────────────────────────────────────────


def test_old_idle_case_is_archived(env):
    _make_case(env.redis, "c1", updated_days_ago=60)
    result = retention.run_retention_cycle(now=NOW)
    assert result["archived"] == ["c1"]
    assert env.calls["archive"] == ["c1"]
    case = env.redis.hgetall("case:c1")
    assert case["status"] == "archived"
    assert case["archived_at"]  # stamped for the purge countdown
    # Audit trail recorded the action as the retention system actor.
    assert any(a["case_id"] == "c1" and a["actor"] == "system:retention"
               and a["status"] == 200 for a in env.calls["audit"])


def test_fresh_case_is_untouched(env):
    _make_case(env.redis, "c1", updated_days_ago=2)
    result = retention.run_retention_cycle(now=NOW)
    assert result["archived"] == []
    assert env.calls["archive"] == []
    assert env.redis.hget("case:c1", "status") == "active"


def test_case_with_active_jobs_is_skipped(env):
    _make_case(env.redis, "c1", updated_days_ago=90)
    job_svc.create_job("j1", "c1", "disk.E01", "cases/c1/disk.E01")
    job_svc.update_job("j1", status="RUNNING")
    result = retention.run_retention_cycle(now=NOW)
    assert result["archived"] == []
    assert result["skipped_busy"] == ["c1"]
    assert env.calls["archive"] == []
    assert env.redis.hget("case:c1", "status") == "active"


def test_case_with_only_finished_jobs_is_archived(env):
    _make_case(env.redis, "c1", updated_days_ago=90)
    job_svc.create_job("j1", "c1", "disk.E01", "cases/c1/disk.E01")
    job_svc.update_job("j1", status="COMPLETED")
    result = retention.run_retention_cycle(now=NOW)
    assert result["archived"] == ["c1"]


def test_malware_sentinel_case_is_never_touched(env):
    _make_case(env.redis, "__malware__", updated_days_ago=365)
    result = retention.run_retention_cycle(now=NOW)
    assert result["archived"] == []
    assert result["purged"] == []
    assert env.calls["archive"] == []
    assert env.redis.hget("case:__malware__", "status") == "active"


# ── Purge decisions ───────────────────────────────────────────────────────────


def test_long_archived_case_is_purged(env):
    _make_case(env.redis, "c1", status="archived", updated_days_ago=80,
               archived_at=_iso(45))
    result = retention.run_retention_cycle(now=NOW)
    assert result["purged"] == ["c1"]
    assert env.calls["purge"] == ["c1"]
    assert any(a["case_id"] == "c1" and a["status"] == 200 for a in env.calls["audit"])


def test_recently_archived_case_is_not_purged(env):
    _make_case(env.redis, "c1", status="archived", updated_days_ago=10,
               archived_at=_iso(5))
    result = retention.run_retention_cycle(now=NOW)
    assert result["purged"] == []
    assert env.calls["purge"] == []


def test_already_purged_case_is_not_purged_again(env):
    _make_case(env.redis, "c1", status="archived", updated_days_ago=365,
               archived_at=_iso(300), local_purged="true")
    result = retention.run_retention_cycle(now=NOW)
    assert result["purged"] == []
    assert env.calls["purge"] == []


def test_purge_falls_back_to_updated_at_without_archived_at(env):
    # Cases archived before the archived_at field existed still purge on schedule.
    _make_case(env.redis, "c1", status="archived", updated_days_ago=60)
    result = retention.run_retention_cycle(now=NOW)
    assert result["purged"] == ["c1"]


def test_archived_case_with_active_jobs_is_not_purged(env):
    _make_case(env.redis, "c1", status="archived", updated_days_ago=80,
               archived_at=_iso(45))
    job_svc.create_job("j1", "c1", "disk.E01", "cases/c1/disk.E01")
    job_svc.update_job("j1", status="PENDING")
    result = retention.run_retention_cycle(now=NOW)
    assert result["purged"] == []
    assert result["skipped_busy"] == ["c1"]


# ── Scheduler-level guards ────────────────────────────────────────────────────


def test_scheduler_disabled_when_archive_after_is_zero(env, monkeypatch):
    # 0 = off (the default) — nothing happens even to ancient cases.
    monkeypatch.setattr(retention, "_retention_config", lambda: (0, 30))
    _make_case(env.redis, "c1", updated_days_ago=365)
    _make_case(env.redis, "c2", status="archived", updated_days_ago=365,
               archived_at=_iso(300))
    result = retention.run_retention_cycle(now=NOW)
    assert result == {"archived": [], "purged": [], "skipped_busy": [], "errors": []}
    assert env.calls["archive"] == [] and env.calls["purge"] == []


def test_sweep_skips_when_archive_s3_not_configured(env):
    env.redis.delete(rk.ARCHIVE_SETTINGS)
    _make_case(env.redis, "c1", updated_days_ago=365)
    result = retention.run_retention_cycle(now=NOW)
    assert result["archived"] == []
    assert result["errors"] == ["archive S3 not configured"]
    assert env.calls["archive"] == []


def test_archive_failure_is_audited_and_isolated(env, monkeypatch):
    def _boom(case_id):
        raise RuntimeError("minio down")

    monkeypatch.setattr(retention, "_archive_case", _boom)
    _make_case(env.redis, "c1", updated_days_ago=60)
    _make_case(env.redis, "c2", updated_days_ago=2)  # fresh — proves the sweep continues
    result = retention.run_retention_cycle(now=NOW)
    assert result["errors"] == ["c1"]
    assert env.redis.hget("case:c1", "status") == "active"  # not flipped on failure
    assert any(a["case_id"] == "c1" and a["status"] == 500 for a in env.calls["audit"])
