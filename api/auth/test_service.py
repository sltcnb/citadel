"""Unit tests for auth.service — JWT lifecycle, revocation, user CRUD, secret stripping.

Uses the fakeredis `fake_redis` fixture from api/conftest.py.
"""

import sys
from pathlib import Path

import pytest
from jose import JWTError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auth import service as svc  # noqa: E402
from config import settings  # noqa: E402


# ── JWT ─────────────────────────────────────────────────────────────────────


def test_token_round_trip():
    token = svc.create_token("alice", "analyst")
    payload = svc.decode_token(token)
    assert payload["sub"] == "alice"
    assert payload["role"] == "analyst"
    assert payload["jti"]


def test_expired_token_rejected(monkeypatch):
    monkeypatch.setattr(settings, "JWT_EXPIRE_HOURS", -1)  # already expired
    token = svc.create_token("bob", "admin")
    with pytest.raises(JWTError):
        svc.decode_token(token)


def test_tampered_token_rejected():
    token = svc.create_token("carol", "admin")
    with pytest.raises(JWTError):
        svc.decode_token(token + "tampered")


def test_revocation_flow(fake_redis):
    token = svc.create_token("dave", "analyst")
    payload = svc.decode_token(token)
    assert svc.is_token_revoked(payload) is False
    svc.revoke_token(token)
    assert svc.is_token_revoked(payload) is True


def test_revoked_check_false_when_no_jti(fake_redis):
    assert svc.is_token_revoked({"sub": "x"}) is False


# ── User CRUD ────────────────────────────────────────────────────────────────


def test_create_user_strips_secrets_and_parses_companies(fake_redis):
    pub = svc.create_user("eve", "pw123!", role="analyst", companies=["Acme"])
    assert pub["username"] == "eve"
    assert pub["role"] == "analyst"
    assert pub["companies"] == ["Acme"]
    # No secret fields leak through _public.
    for secret in ("hashed_password", "totp_secret", "totp_pending_secret", "totp_backup"):
        assert secret not in pub


def test_create_user_duplicate_raises(fake_redis):
    svc.create_user("frank", "pw", role="admin")
    with pytest.raises(ValueError, match="already exists"):
        svc.create_user("frank", "pw2", role="admin")


def test_create_user_invalid_role_raises(fake_redis):
    with pytest.raises(ValueError, match="Invalid role"):
        svc.create_user("grace", "pw", role="superuser")


def test_authenticate(fake_redis):
    svc.create_user("heidi", "s3cret!", role="analyst")
    assert svc.authenticate("heidi", "s3cret!") is not None
    assert svc.authenticate("heidi", "wrong") is None
    assert svc.authenticate("nobody", "x") is None


def test_update_user_not_found_raises(fake_redis):
    with pytest.raises(ValueError, match="not found"):
        svc.update_user("ghost", role="admin")


def test_update_user_invalid_role_raises(fake_redis):
    svc.create_user("ivan", "pw", role="analyst")
    with pytest.raises(ValueError, match="Invalid role"):
        svc.update_user("ivan", role="root")


def test_delete_user(fake_redis):
    svc.create_user("judy", "pw", role="analyst")
    assert svc.delete_user("judy") is True
    assert svc.delete_user("judy") is False
    assert svc.get_user("judy") is None


def test_list_users_strips_secrets(fake_redis):
    svc.create_user("ken", "pw", role="admin", companies=["X"])
    users = svc.list_users()
    assert any(u["username"] == "ken" for u in users)
    assert all("hashed_password" not in u for u in users)
