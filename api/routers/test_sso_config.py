"""Tests for the Redis-backed admin SSO config (GET/PUT) and the
Redis-overrides-env resolution used by the public providers list.

These exercise the endpoint handler functions directly (no live FastAPI app /
auth) with a fakeredis patched into the module's Redis accessor, mirroring the
fakeredis pattern in api/conftest.py.
"""

import sys
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import settings  # noqa: E402
from routers import sso  # noqa: E402


@pytest.fixture
def fake_redis(monkeypatch):
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(sso, "_get_redis", lambda: fake, raising=True)
    return fake


def _put(**kw):
    body = sso.SSOConfigIn(**kw)
    return sso.update_sso_config(body)


def test_put_then_get_redacts_secret(fake_redis):
    out = _put(
        google_client_id="gid",
        google_client_secret="gsecret",
        microsoft_client_id="mid",
        microsoft_client_secret="msecret",
        microsoft_tenant="tenant-guid",
        redirect_base="https://citadel.example.com/",
        allowed_domains=["Acme.COM", " ", "beta.io"],
        default_role="analyst",
        auto_provision=True,
    )
    # PUT response is already redacted.
    assert "google_client_secret" not in out
    assert out["google_secret_set"] is True
    assert out["microsoft_secret_set"] is True
    assert out["google_client_id"] == "gid"
    # redirect_base trailing slash stripped; domains normalised/cleaned.
    assert out["redirect_base"] == "https://citadel.example.com"
    assert out["allowed_domains"] == ["acme.com", "beta.io"]
    # callback_base hint reflects the redirect_base.
    assert (
        out["callback_base"]["google"]
        == "https://citadel.example.com/api/v1/auth/sso/google/callback"
    )

    got = sso.get_sso_config()
    assert got["google_secret_set"] is True
    assert "google_client_secret" not in got
    assert got["microsoft_tenant"] == "tenant-guid"
    assert got["default_role"] == "analyst"


def test_blank_secret_on_reput_preserves_existing(fake_redis):
    _put(google_client_id="gid", google_client_secret="topsecret")
    # Re-PUT with a blank secret but changed client id.
    out = _put(google_client_id="gid2", google_client_secret="")
    assert out["google_secret_set"] is True  # preserved
    assert out["google_client_id"] == "gid2"
    # The actual stored secret is still the original.
    assert sso._client_secret("google") == "topsecret"


def test_providers_list_reflects_stored_config(fake_redis, monkeypatch):
    # Ensure env defaults are empty so only Redis config counts.
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "")
    monkeypatch.setattr(settings, "MICROSOFT_CLIENT_ID", "")
    monkeypatch.setattr(settings, "MICROSOFT_CLIENT_SECRET", "")

    assert sso.enabled_providers() == []  # nothing stored, nothing in env

    _put(google_client_id="gid", google_client_secret="gsec")
    ids = [p["id"] for p in sso.enabled_providers()]
    assert ids == ["google"]
    assert sso.is_configured("google") is True
    assert sso.is_configured("microsoft") is False


def test_redis_overrides_env(fake_redis, monkeypatch):
    # Env default present...
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "env-id")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "env-secret")
    assert sso._client_id("google") == "env-id"  # falls back to env

    # ...but Redis takes precedence once stored.
    _put(google_client_id="redis-id", google_client_secret="redis-secret")
    assert sso._client_id("google") == "redis-id"
    assert sso._client_secret("google") == "redis-secret"


def test_invalid_default_role_rejected(fake_redis):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        _put(default_role="superadmin")
    assert exc.value.status_code == 400
