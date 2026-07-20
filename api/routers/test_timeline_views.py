"""Unit tests for the saved timeline views router (Redis-backed, per case).

Mirrors the fakeredis pattern used across the router test suite: a
FakeRedis(decode_responses=True) patched into the module's ``_r`` accessor so
create/list/delete can be exercised without a live Redis or FastAPI app.
"""

import sys
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routers import timeline_views as tv  # noqa: E402


@pytest.fixture
def fake(monkeypatch):
    r = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(tv, "_r", lambda: r, raising=True)
    return r


def _view_in(**overrides):
    data = {
        "name": "Lateral movement",
        "query": "process.name:psexec.exe",
        "selected_types": "evtx,hayabusa",
        "level": "high",
        "flagged": True,
        "from_ts": "2026-01-01T00:00:00Z",
        "to_ts": "2026-01-02T00:00:00Z",
        "columns": ["timestamp", "host", "user", "message"],
        "sort_field": "timestamp",
        "sort_order": "desc",
    }
    data.update(overrides)
    return tv.TimelineViewIn(**data)


def test_list_empty_when_no_views(fake):
    assert tv.list_timeline_views("case1", _case={}) == {"views": []}


def test_create_returns_persisted_view(fake):
    created = tv.create_timeline_view("case1", _view_in(), _case={})
    assert created["name"] == "Lateral movement"
    assert created["selected_types"] == "evtx,hayabusa"
    assert created["flagged"] is True
    assert created["columns"] == ["timestamp", "host", "user", "message"]
    assert "id" in created and "created_at" in created

    listed = tv.list_timeline_views("case1", _case={})
    assert listed["views"] == [created]


def test_views_are_scoped_per_case(fake):
    tv.create_timeline_view("case1", _view_in(name="A"), _case={})
    tv.create_timeline_view("case2", _view_in(name="B"), _case={})
    assert [v["name"] for v in tv.list_timeline_views("case1", _case={})["views"]] == ["A"]
    assert [v["name"] for v in tv.list_timeline_views("case2", _case={})["views"]] == ["B"]


def test_delete_removes_only_target_view(fake):
    v1 = tv.create_timeline_view("case1", _view_in(name="Keep"), _case={})
    v2 = tv.create_timeline_view("case1", _view_in(name="Drop"), _case={})
    tv.delete_timeline_view("case1", v2["id"], _case={})
    remaining = tv.list_timeline_views("case1", _case={})["views"]
    assert [v["id"] for v in remaining] == [v1["id"]]


def test_delete_unknown_id_is_a_noop(fake):
    tv.create_timeline_view("case1", _view_in(), _case={})
    tv.delete_timeline_view("case1", "nonexistent", _case={})
    assert len(tv.list_timeline_views("case1", _case={})["views"]) == 1
