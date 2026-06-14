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


def test_builtin_is_readonly(ct):
    with pytest.raises(HTTPException) as e1:
        ct.update_template("ransomware", data={"name": "x"}, _={"role": "admin"})
    assert e1.value.status_code == 400

    with pytest.raises(HTTPException) as e2:
        ct.delete_template("ransomware", _={"role": "admin"})
    assert e2.value.status_code == 400

    # builtin still resolves and is tagged read-only
    assert ct._get_template("ransomware")["builtin"] is True


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
