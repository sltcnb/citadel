"""Unit tests for the editable custom case-template store.

Exercises the resolver + CRUD helpers directly (no FastAPI app), with the
module's get_redis patched to a fakeredis instance per the conftest pattern.
"""

import fakeredis
import pytest
from fastapi import HTTPException


@pytest.fixture
def ct(monkeypatch):
    import routers.case_templates as mod

    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(mod, "get_redis", lambda: fake, raising=True)
    return mod


def test_create_list_update_delete(ct):
    # create
    created = ct.create_template(
        data={
            "name": "BEC Investigation",
            "description": "desc",
            "tags": ["bec", "phishing"],
            "watchlist": [{"kind": "domain", "value": "evil.com", "label": "C2"}],
            "rule_categories": ["sigma_hq/01_initial_access"],
            "notes": "# notes",
        },
        _={"role": "admin"},
    )
    tid = created["id"]
    assert tid == "bec-investigation"
    assert created["builtin"] is False

    # list includes builtins (first) + the new custom one with the flag
    listing = ct.list_templates(_={"role": "admin"})["templates"]
    ids = [t["id"] for t in listing]
    assert "ransomware" in ids and tid in ids
    custom = next(t for t in listing if t["id"] == tid)
    assert custom["builtin"] is False and custom["watchlist_count"] == 1
    assert next(t for t in listing if t["id"] == "ransomware")["builtin"] is True

    # full object is editable
    full = ct.get_template_full(tid, _={"role": "admin"})
    assert full["notes"] == "# notes" and full["watchlist"][0]["value"] == "evil.com"

    # update
    updated = ct.update_template(
        tid,
        data={"name": "BEC v2", "watchlist": [{"kind": "ip", "value": "1.2.3.4"}]},
        _={"role": "admin"},
    )
    assert updated["name"] == "BEC v2"
    assert ct.get_template_full(tid, _={"role": "admin"})["watchlist"][0]["kind"] == "ip"

    # delete
    ct.delete_template(tid, _={"role": "admin"})
    assert ct._get_template(tid) is None
    with pytest.raises(HTTPException) as e:
        ct.get_template_full(tid, _={"role": "admin"})
    assert e.value.status_code == 404


def test_builtin_editable_via_override(ct):
    # A pristine built-in has nothing to reset.
    with pytest.raises(HTTPException) as e0:
        ct.delete_template("ransomware", _={"role": "admin"})
    assert e0.value.status_code == 400

    # Editing a built-in persists an override: it still reports builtin=True
    # but is now flagged overridden, and the new content resolves.
    updated = ct.update_template(
        "ransomware",
        data={"name": "Ransomware (tuned)", "watchlist": [{"kind": "ip", "value": "9.9.9.9"}]},
        _={"role": "admin"},
    )
    assert updated["builtin"] is True and updated["overridden"] is True
    resolved = ct._get_template("ransomware")
    assert resolved["builtin"] is True and resolved["overridden"] is True
    assert resolved["name"] == "Ransomware (tuned)"

    # It appears once in the listing (override shadows the built-in), flagged.
    listing = ct.list_templates(_={"role": "admin"})["templates"]
    rows = [t for t in listing if t["id"] == "ransomware"]
    assert len(rows) == 1 and rows[0]["builtin"] is True and rows[0]["overridden"] is True

    # Reset (delete the override) restores the shipped default.
    ct.delete_template("ransomware", _={"role": "admin"})
    restored = ct._get_template("ransomware")
    assert restored["builtin"] is True and not restored.get("overridden")
    assert restored["name"] != "Ransomware (tuned)"


def test_slug_dedupe_and_validation(ct):
    a = ct.create_template(data={"name": "Dup"}, _={"role": "admin"})
    b = ct.create_template(data={"name": "Dup"}, _={"role": "admin"})
    assert a["id"] == "dup" and b["id"] == "dup-2"

    with pytest.raises(HTTPException) as e:
        ct.create_template(data={"name": "  "}, _={"role": "admin"})
    assert e.value.status_code == 400

    with pytest.raises(HTTPException) as e2:
        ct.create_template(
            data={"name": "Bad", "watchlist": [{"kind": "ip"}]}, _={"role": "admin"}
        )
    assert e2.value.status_code == 400
