"""Regression tests for the auth/admin security fixes:

- password/role change invalidates outstanding tokens (tokens_valid_after)
- group membership via the group ``members`` picker grants effective access
- readiness probe returns HTTP 503 when a dependency is down
- SSO auto-provision enforces the plan seat limit

Uses the fakeredis `fake_redis` fixture from api/conftest.py.
"""

import asyncio
import json
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auth import rbac  # noqa: E402
from auth import service as svc
from auth.dependencies import get_current_user  # noqa: E402


class _Req:
    """Minimal stand-in for fastapi.Request (no bearer header, no query token)."""

    query_params: dict = {}


def _current_user(token: str) -> dict:
    return asyncio.run(get_current_user(_Req(), token))


def _groups_of(username: str) -> list:
    return json.loads(svc.get_user(username)["groups"])


# ── Token invalidation on password / role change ──────────────────────────────


def test_old_token_rejected_after_password_change(fake_redis):
    svc.create_user("mallory", "old-pw-1234", role="analyst")
    token = svc.create_token("mallory", "analyst")
    assert _current_user(token)["username"] == "mallory"  # valid before

    svc.update_user("mallory", password="new-pw-1234")

    with pytest.raises(HTTPException) as ei:
        _current_user(token)
    assert ei.value.status_code == 401
    # A token minted AFTER the change still works.
    fresh = svc.create_token("mallory", "analyst")
    assert _current_user(fresh)["username"] == "mallory"


def test_old_token_rejected_after_role_change(fake_redis):
    svc.create_user("nadia", "pw-12345678", role="analyst")
    token = svc.create_token("nadia", "analyst")
    svc.update_user("nadia", role="guest")
    with pytest.raises(HTTPException) as ei:
        _current_user(token)
    assert ei.value.status_code == 401


def test_update_password_and_change_role_also_invalidate(fake_redis):
    svc.create_user("olga", "pw-12345678", role="analyst")
    t1 = svc.create_token("olga", "analyst")
    assert svc.update_password("olga", "pw-87654321") is True
    assert not svc.tokens_valid_for_user(svc.get_user("olga"), svc.decode_token(t1))
    t2 = svc.create_token("olga", "analyst")
    assert svc.change_role("olga", "developer") is True
    assert not svc.tokens_valid_for_user(svc.get_user("olga"), svc.decode_token(t2))


def test_unrelated_update_keeps_tokens_valid(fake_redis):
    svc.create_user("pat", "pw-12345678", role="analyst")
    token = svc.create_token("pat", "analyst")
    svc.update_user("pat", companies=["Acme"])  # scope edit, not a credential change
    assert _current_user(token)["username"] == "pat"


# ── Group members picker grants effective access (canonical: user.groups) ─────


def test_group_members_picker_grants_effective_permissions(fake_redis):
    svc.create_user("quinn", "pw-12345678", role="guest")  # guest = cases.read only
    group = svc.create_group(
        "IR Team",
        permissions=[rbac.CASES_WRITE, rbac.MODULES_RUN],
        companies=["Acme"],
    )
    # Add the user via the GROUP side (the members picker), not via user edit.
    svc.update_group(group["id"], members=["quinn"])

    user = svc.get_user("quinn")
    perms = rbac.effective_permissions(
        {**user, "groups": _groups_of("quinn")}, svc.groups_index()
    )
    assert rbac.CASES_WRITE in perms
    assert rbac.MODULES_RUN in perms
    companies = rbac.effective_companies(
        {**user, "groups": _groups_of("quinn")}, svc.groups_index()
    )
    assert companies == ["Acme"]
    # The effective view (group.members) and enforcement (user.groups) agree.
    assert "quinn" in svc.get_group(group["id"])["members"]


def test_group_members_picker_removal_revokes(fake_redis):
    svc.create_user("ruth", "pw-12345678", role="guest")
    group = svc.create_group("IR Team", permissions=[rbac.CASES_WRITE])
    svc.update_group(group["id"], members=["ruth"])
    svc.update_group(group["id"], members=[])  # remove again
    assert _groups_of("ruth") == []
    assert svc.get_group(group["id"])["members"] == []


def test_user_groups_edit_syncs_group_members(fake_redis):
    svc.create_user("sam", "pw-12345678", role="analyst")
    group = svc.create_group("Blue Team")
    svc.update_user("sam", groups=[group["id"]])
    assert "sam" in svc.get_group(group["id"])["members"]
    svc.update_user("sam", groups=[])
    assert svc.get_group(group["id"])["members"] == []


def test_delete_group_strips_membership(fake_redis):
    svc.create_user("tess", "pw-12345678", role="analyst")
    group = svc.create_group("Red Team", members=["tess"])
    assert group["id"] in _groups_of("tess")
    svc.delete_group(group["id"])
    assert _groups_of("tess") == []


# ── Readiness probe status codes ───────────────────────────────────────────────


def test_readiness_200_when_deps_ok(monkeypatch):
    from routers import health

    monkeypatch.setattr(health, "_check_es", lambda: True)
    monkeypatch.setattr(health, "_check_redis", lambda: True)
    body = health.readiness()
    assert body["status"] == "ready"


def test_readiness_503_when_deps_down(monkeypatch):
    from routers import health

    monkeypatch.setattr(health, "_check_es", lambda: False)
    monkeypatch.setattr(health, "_check_redis", lambda: True)
    resp = health.readiness()
    assert resp.status_code == 503

    monkeypatch.setattr(health, "_check_es", lambda: True)
    monkeypatch.setattr(health, "_check_redis", lambda: False)
    assert health.readiness().status_code == 503


# ── SSO auto-provision respects the seat limit ─────────────────────────────────


def _license(monkeypatch, max_users):
    import license.gate as gate
    import license.models as lm

    info = lm.LicenseInfo(
        valid=True, plan="community", org_name="Community", seats=max_users,
        valid_until=None, features={"max_users": max_users},
    )
    monkeypatch.setattr(gate, "get_license", lambda: info)


def test_sso_provision_enforces_seat_limit(fake_redis, monkeypatch):
    from routers import sso

    _license(monkeypatch, max_users=1)
    svc.create_user("existing@acme.com", "pw-12345678", role="analyst")

    with pytest.raises(HTTPException) as ei:
        sso.provision_user("new@acme.com", "New User", "google")
    assert ei.value.status_code == 402
    assert svc.get_user("new@acme.com") is None


def test_sso_provision_within_seat_limit(fake_redis, monkeypatch):
    from routers import sso

    _license(monkeypatch, max_users=5)
    assert sso.provision_user("new@acme.com", "New User", "google") is True
    assert svc.get_user("new@acme.com") is not None


# ── Replay protections (pw_token, TOTP code, backup codes) ────────────────────


def test_pw_token_single_use(fake_redis):
    svc.create_user("u1", "pw-12345678", role="analyst")
    chal = svc.create_pw_change_challenge("u1")
    assert svc.decode_pw_change_challenge(chal) == "u1"
    svc.revoke_token(chal)  # what login_change_password does after success
    assert svc.decode_pw_change_challenge(chal) is None


def test_totp_replay_cache(fake_redis):
    # The cache claim is atomic: first presentation wins, replay is refused.
    assert svc._mark_totp_code_used("u2", "123456") is True
    assert svc._mark_totp_code_used("u2", "123456") is False
    assert svc._mark_totp_code_used("u2", "654321") is True  # different code OK
    assert svc._mark_totp_code_used("u3", "123456") is True  # different user OK


def test_backup_code_consumed_once(fake_redis):
    svc.create_user("u4", "pw-12345678")
    h = svc.hash_password("abcd1234")
    fake_redis.hset(
        svc.rk.user_key("u4"),
        mapping={"totp_enabled": "1", "totp_backup": json.dumps([h])},
    )
    assert svc._consume_backup_code("u4", "abcd1234", svc.get_user("u4")) is True
    assert svc._consume_backup_code("u4", "abcd1234", svc.get_user("u4")) is False


# ── Session idle timeout (session_idle_minutes) ───────────────────────────────


def test_idle_timeout_enforced(fake_redis, monkeypatch):
    import routers.platform_settings as ps

    import auth.dependencies as deps
    import config

    monkeypatch.setattr(ps, "_redis", lambda: fake_redis)
    monkeypatch.setattr(config, "get_redis", lambda: fake_redis)
    fake_redis.set("fo:config:platform", json.dumps({"session_idle_minutes": 5}))

    svc.create_user("u5", "pw-12345678")
    tok = svc.create_token("u5", "analyst")
    jti = svc.decode_token(tok)["jti"]
    assert fake_redis.exists(f"fo:session:active:{jti}") == 1  # seeded at login

    user = _current_user(tok)
    assert user["username"] == "u5"

    deps._USER_CACHE.clear()
    fake_redis.delete(f"fo:session:active:{jti}")  # idle window elapsed
    with pytest.raises(HTTPException) as ei:
        _current_user(tok)
    assert ei.value.status_code == 401

    # Disabled setting → no idle enforcement even with no activity key.
    fake_redis.set("fo:config:platform", json.dumps({"session_idle_minutes": 0}))
    deps._USER_CACHE.clear()
    assert _current_user(tok)["username"] == "u5"
