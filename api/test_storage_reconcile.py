"""Unit tests for orphan detection and reconcile semantics.

MinIO listing/deletion is mocked; the DB known-key set is injected.
"""

from datetime import UTC, datetime, timedelta


from services import storage, storage_reconcile as sr


class _Obj:
    def __init__(self, name, age_hours=100):
        self.object_name = name
        self.last_modified = datetime.now(UTC) - timedelta(hours=age_hours)


def _setup(monkeypatch, objects, known):
    deleted = []
    monkeypatch.setattr(
        storage,
        "list_objects",
        lambda prefix, recursive=True: iter(
            [o for o in objects if o.object_name.startswith(prefix)]
        ),
    )
    monkeypatch.setattr(storage, "delete_object", lambda k: deleted.append(k))
    monkeypatch.setattr(sr, "known_object_keys", lambda: set(known))
    return deleted


def test_find_orphans_classifies(monkeypatch):
    objects = [
        _Obj("cases/c1/a"),  # known -> ok
        _Obj("cases/c1/b"),  # unknown, old -> orphan
        _Obj("cases/c1/new", age_hours=1),  # unknown, recent -> skipped
    ]
    known = {"cases/c1/a", "cases/c1/missing"}  # missing has no object
    _setup(monkeypatch, objects, known)

    report = sr.find_orphans()
    assert report.orphan_objects == ["cases/c1/b"]
    assert report.skipped_recent == ["cases/c1/new"]
    assert report.missing_objects == ["cases/c1/missing"]
    assert report.scanned_objects == 3


def test_grace_period_guard(monkeypatch):
    objects = [_Obj("cases/c1/recent", age_hours=2)]
    _setup(monkeypatch, objects, set())
    # Default 24h grace -> recent object is protected, not an orphan.
    report = sr.find_orphans()
    assert report.orphan_objects == []
    assert report.skipped_recent == ["cases/c1/recent"]
    # Shrinking the grace window below the object age reclassifies it.
    report2 = sr.find_orphans(grace_hours=1)
    assert report2.orphan_objects == ["cases/c1/recent"]


def test_reconcile_dry_run_deletes_nothing(monkeypatch):
    objects = [_Obj("cases/c1/orphan")]
    deleted = _setup(monkeypatch, objects, set())
    result = sr.reconcile(dry_run=True)
    assert result["action"] == "report-only"
    assert result["would_delete"] == ["cases/c1/orphan"]
    assert result["deleted"] == []
    assert deleted == []


def test_reconcile_requires_confirm(monkeypatch):
    objects = [_Obj("cases/c1/orphan")]
    deleted = _setup(monkeypatch, objects, set())
    # dry_run=False but confirm not set -> still no deletion.
    result = sr.reconcile(dry_run=False, confirm=False)
    assert result["action"] == "report-only"
    assert deleted == []


def test_reconcile_confirmed_deletes_only_orphans(monkeypatch):
    objects = [_Obj("cases/c1/orphan"), _Obj("cases/c1/keep")]
    deleted = _setup(monkeypatch, objects, {"cases/c1/keep"})
    result = sr.reconcile(dry_run=False, confirm=True)
    assert result["action"] == "deleted"
    assert deleted == ["cases/c1/orphan"]
    assert result["deleted"] == ["cases/c1/orphan"]


def test_reconcile_never_deletes_recent(monkeypatch):
    objects = [_Obj("cases/c1/recent", age_hours=1)]
    deleted = _setup(monkeypatch, objects, set())
    result = sr.reconcile(dry_run=False, confirm=True)
    assert deleted == []
    assert result["deleted"] == []


def test_max_objects_truncates(monkeypatch):
    objects = [_Obj(f"cases/c1/{i}") for i in range(5)]
    _setup(monkeypatch, objects, set())
    report = sr.find_orphans(max_objects=2)
    assert report.truncated is True
    assert report.scanned_objects == 2


# ── Scheduled (report-only) sweep ───────────────────────────────────────────────


class _FakeRedis:
    def __init__(self):
        self.kv = {}

    def set(self, k, v, **kw):
        self.kv[k] = v
        return True

    def get(self, k):
        return self.kv.get(k)


def test_scheduled_reconcile_disabled_returns_none(monkeypatch):
    monkeypatch.setattr(sr.settings, "STORAGE_RECONCILE_SCHEDULE_ENABLED", False)
    assert sr.run_scheduled_reconcile() is None


def test_scheduled_reconcile_dry_run_stores_report_no_delete(monkeypatch):
    objects = [_Obj("cases/c1/orphan"), _Obj("cases/c1/keep")]
    deleted = _setup(monkeypatch, objects, {"cases/c1/keep"})
    monkeypatch.setattr(sr.settings, "STORAGE_RECONCILE_SCHEDULE_ENABLED", True)

    fake = _FakeRedis()
    import config

    monkeypatch.setattr(config, "get_redis", lambda: fake)

    payload = sr.run_scheduled_reconcile()
    # Report-only: it classified the orphan but deleted nothing.
    assert payload["mode"] == "report-only"
    assert payload["orphan_objects"] == ["cases/c1/orphan"]
    assert deleted == []
    # The latest report was persisted to Redis for later surfacing.
    import json as _json

    stored = _json.loads(fake.get(sr.LATEST_REPORT_KEY))
    assert stored["orphan_objects"] == ["cases/c1/orphan"]
    assert "generated_at" in stored
    assert sr.latest_report()["orphan_objects"] == ["cases/c1/orphan"]
