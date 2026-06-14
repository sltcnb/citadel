"""Tests for the SSO pure helpers (no network): provider-config detection,
authorize-URL building, and the email-domain allowlist."""

import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import settings  # noqa: E402
from routers import sso  # noqa: E402


def _set(monkeypatch, **kw):
    for k, v in kw.items():
        monkeypatch.setattr(settings, k, v)


def test_provider_disabled_without_credentials(monkeypatch):
    _set(monkeypatch, GOOGLE_CLIENT_ID="", GOOGLE_CLIENT_SECRET="",
         MICROSOFT_CLIENT_ID="", MICROSOFT_CLIENT_SECRET="")
    assert sso.enabled_providers() == []
    assert sso.is_configured("google") is False


def test_provider_enabled_when_both_set(monkeypatch):
    _set(monkeypatch, GOOGLE_CLIENT_ID="gid", GOOGLE_CLIENT_SECRET="gsec",
         MICROSOFT_CLIENT_ID="", MICROSOFT_CLIENT_SECRET="")
    ids = [p["id"] for p in sso.enabled_providers()]
    assert ids == ["google"]
    assert sso.is_configured("google") is True
    assert sso.is_configured("microsoft") is False


def test_authorize_url_has_required_params(monkeypatch):
    _set(monkeypatch, GOOGLE_CLIENT_ID="gid", GOOGLE_CLIENT_SECRET="gsec",
         SSO_REDIRECT_BASE="https://citadel.example.com")
    url = sso.build_authorize_url("google", state="st8", nonce="non")
    base, q = url.split("?", 1)
    assert base == "https://accounts.google.com/o/oauth2/v2/auth"
    p = dict(urllib.parse.parse_qsl(q))
    assert p["client_id"] == "gid"
    assert p["response_type"] == "code"
    assert "openid" in p["scope"] and "email" in p["scope"]
    assert p["state"] == "st8" and p["nonce"] == "non"
    assert p["redirect_uri"] == "https://citadel.example.com/api/v1/auth/sso/google/callback"


def test_microsoft_tenant_substituted(monkeypatch):
    _set(monkeypatch, MICROSOFT_CLIENT_ID="mid", MICROSOFT_CLIENT_SECRET="msec",
         MICROSOFT_TENANT="my-tenant-guid", SSO_REDIRECT_BASE="https://c.example.com")
    url = sso.build_authorize_url("microsoft", state="s", nonce="n")
    assert "login.microsoftonline.com/my-tenant-guid/oauth2/v2.0/authorize" in url


def test_email_allowlist(monkeypatch):
    _set(monkeypatch, SSO_ALLOWED_DOMAINS=[])
    assert sso.email_allowed("anyone@whatever.com") is True   # empty allowlist = allow
    assert sso.email_allowed("not-an-email") is False
    _set(monkeypatch, SSO_ALLOWED_DOMAINS=["acme.com"])
    assert sso.email_allowed("alice@acme.com") is True
    assert sso.email_allowed("alice@ACME.com") is True        # case-insensitive
    assert sso.email_allowed("bob@evil.com") is False
