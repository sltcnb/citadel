"""Single Sign-On router — OIDC authorization-code flow for Google + Microsoft.

SSO is entirely opt-in: a provider only appears (and its endpoints only work)
when both its client_id and client_secret are configured in settings. The flow:

    GET /auth/sso/providers          → which buttons the Login page should show
    GET /auth/sso/{provider}/login   → 307 → provider authorize page
    GET /auth/sso/{provider}/callback→ verify id_token, mint Citadel JWT,
                                        307 → {base}/login#sso_token=<jwt>

All three routes are PUBLIC (no auth dependency) — they ARE the way an
unauthenticated browser obtains a Citadel session. Every network call is
wrapped so a provider hiccup redirects to /login#sso_error=… rather than
returning a 500/stack trace.

The pure, network-free helpers (enabled_providers, build_authorize_url,
email_allowed, provision_user) are factored out so they can be unit-tested
without Redis or HTTP; the route handlers only orchestrate them.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
import urllib.parse

import redis_keys as rk
import requests
from auth.dependencies import require_admin
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from auth import service
from config import get_redis as _get_redis
from config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/sso", tags=["sso"])

# Admin config router (mounted under /api/v1, same as llm_config's /admin/*).
admin_router = APIRouter(tags=["sso"])
_admin_dep = [Depends(require_admin)]

_VALID_ROLES = ("admin", "analyst", "developer", "guest")

# Redis state TTL (CSRF token lifetime) and HTTP timeouts.
_STATE_TTL_SECONDS = 600  # 10 minutes to complete the round-trip
_HTTP_TIMEOUT = 10  # seconds for token exchange / JWKS fetch
_JWKS_CACHE_SECONDS = 3600  # cache provider signing keys for an hour


# ── Provider table ──────────────────────────────────────────────────────────
# Each entry's URL fields are either literals or contain {tenant}/{tid}
# placeholders (Microsoft). issuer may contain {tid}, resolved per-token.


def _ms(path: str) -> str:
    return f"https://login.microsoftonline.com/{{tenant}}{path}"


PROVIDERS: dict[str, dict] = {
    "google": {
        "name": "Google",
        "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
        "token": "https://oauth2.googleapis.com/token",
        "jwks": "https://www.googleapis.com/oauth2/v3/certs",
        "issuer": "https://accounts.google.com",
        "client_id_attr": "GOOGLE_CLIENT_ID",
        "client_secret_attr": "GOOGLE_CLIENT_SECRET",
        "conf_id_key": "google_client_id",
        "conf_secret_key": "google_client_secret",
    },
    "microsoft": {
        "name": "Microsoft",
        "authorize": _ms("/oauth2/v2.0/authorize"),
        "token": _ms("/oauth2/v2.0/token"),
        "jwks": _ms("/discovery/v2.0/keys"),
        # Microsoft stamps the tenant GUID (tid) into the issuer, so we verify
        # against a template rather than a fixed string.
        "issuer": "https://login.microsoftonline.com/{tid}/v2.0",
        "client_id_attr": "MICROSOFT_CLIENT_ID",
        "client_secret_attr": "MICROSOFT_CLIENT_SECRET",
        "conf_id_key": "microsoft_client_id",
        "conf_secret_key": "microsoft_client_secret",
    },
}


# ── Config resolution: Redis overrides, env (settings.*) is the fallback ──────
#
# Every credential/policy value is resolved through _sso_conf(): the stored
# Redis config (key fo:config:sso) takes precedence, and the corresponding
# settings.* env var is the default. This keeps env vars working out of the box
# while letting an admin override any field from the UI without a redeploy.


def _stored_conf() -> dict:
    """Load the Redis-backed SSO config (key fo:config:sso); {} if unset."""
    try:
        raw = _get_redis().get(rk.SSO_CONFIG)
    except Exception:
        return {}
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def _sso_conf() -> dict:
    """Merged effective SSO config: Redis values override env-var defaults.

    Returns a dict with every field populated (Redis value if present and
    non-empty, otherwise the settings.* default). ``allowed_domains`` is always
    a lower-cased list.
    """
    stored = _stored_conf()

    def pick(key: str, default):
        val = stored.get(key)
        # Treat empty string / None as "not set" so env default wins.
        return val if (val not in ("", None)) else default

    domains = stored.get("allowed_domains")
    if not isinstance(domains, list) or not domains:
        domains = settings.SSO_ALLOWED_DOMAINS
    domains = [d.strip().lower() for d in domains if d and d.strip()]

    auto = stored.get("auto_provision")
    if auto is None:
        auto = settings.SSO_AUTO_PROVISION

    return {
        "google_client_id": pick("google_client_id", settings.GOOGLE_CLIENT_ID),
        "google_client_secret": pick("google_client_secret", settings.GOOGLE_CLIENT_SECRET),
        "microsoft_client_id": pick("microsoft_client_id", settings.MICROSOFT_CLIENT_ID),
        "microsoft_client_secret": pick(
            "microsoft_client_secret", settings.MICROSOFT_CLIENT_SECRET
        ),
        "microsoft_tenant": pick("microsoft_tenant", settings.MICROSOFT_TENANT),
        "redirect_base": pick("redirect_base", settings.SSO_REDIRECT_BASE).rstrip("/"),
        "allowed_domains": domains,
        "default_role": pick("default_role", settings.SSO_DEFAULT_ROLE),
        "auto_provision": bool(auto),
    }


def _client_id(provider: str) -> str:
    return _sso_conf().get(PROVIDERS[provider]["conf_id_key"], "") or ""


def _client_secret(provider: str) -> str:
    return _sso_conf().get(PROVIDERS[provider]["conf_secret_key"], "") or ""


def _resolve(url: str) -> str:
    """Substitute the Microsoft {tenant} placeholder; no-op for Google."""
    return url.replace("{tenant}", _sso_conf()["microsoft_tenant"])


def is_configured(provider: str) -> bool:
    """A provider is usable only when client_id AND secret are both set."""
    return bool(_client_id(provider)) and bool(_client_secret(provider))


def enabled_providers() -> list[dict]:
    """List configured providers as ``[{"id":..., "name":...}]`` for the UI."""
    return [
        {"id": pid, "name": meta["name"]}
        for pid, meta in PROVIDERS.items()
        if is_configured(pid)
    ]


# ── Pure helpers ─────────────────────────────────────────────────────────────


def callback_url(provider: str) -> str:
    """The redirect_uri registered with the provider for this app."""
    return f"{_sso_conf()['redirect_base']}/api/v1/auth/sso/{provider}/callback"


def build_authorize_url(provider: str, state: str, nonce: str) -> str:
    """Build the provider's authorize URL for the code flow."""
    meta = PROVIDERS[provider]
    params = {
        "client_id": _client_id(provider),
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": callback_url(provider),
        "state": state,
        "nonce": nonce,
        "response_mode": "query",
    }
    return f"{_resolve(meta['authorize'])}?{urllib.parse.urlencode(params)}"


def email_allowed(email: str) -> bool:
    """Enforce SSO_ALLOWED_DOMAINS (case-insensitive). Empty allowlist = allow."""
    if not email or "@" not in email:
        return False
    allowed = _sso_conf()["allowed_domains"]
    if not allowed:
        return True
    domain = email.rsplit("@", 1)[1].lower()
    return domain in allowed


def provision_user(email: str, name: str, provider: str) -> bool:
    """Find-or-provision the Citadel user for a verified SSO email.

    Returns True if a usable Citadel user exists afterwards (existing, or newly
    auto-provisioned), False if the user is absent and auto-provision is off.
    The username is the email. New users get a random password (login is via
    SSO, not this password) and are tagged ``sso_provider``.
    """
    existing = service.get_user(email)
    if existing:
        # Tag the provider on an existing account (best-effort, non-fatal).
        try:
            _get_redis().hset(
                f"fo:user:{email}", mapping={"sso_provider": provider}
            )
        except Exception:
            pass
        return True
    conf = _sso_conf()
    if not conf["auto_provision"]:
        return False
    random_pw = secrets.token_urlsafe(32)
    service.create_user(email, random_pw, role=conf["default_role"])
    try:
        _get_redis().hset(
            f"fo:user:{email}",
            mapping={"sso_provider": provider, "sso_name": name or ""},
        )
    except Exception:
        pass
    return True


# ── State (CSRF) store ───────────────────────────────────────────────────────


def _state_key(state: str) -> str:
    return f"fo:sso:state:{state}"


def _store_state(state: str, provider: str, nonce: str) -> None:
    _get_redis().setex(
        _state_key(state), _STATE_TTL_SECONDS, f"{provider}:{nonce}"
    )


def _consume_state(state: str) -> tuple[str, str] | None:
    """Validate + one-time-delete a state token. Returns (provider, nonce)."""
    if not state:
        return None
    r = _get_redis()
    key = _state_key(state)
    raw = r.get(key)
    if not raw:
        return None
    r.delete(key)  # one-time use
    provider, _, nonce = raw.partition(":")
    return provider, nonce


# ── JWKS fetch + id_token verification (the network seam, stubbable) ─────────

_jwks_cache: dict[str, tuple[float, dict]] = {}


def fetch_jwks(provider: str) -> dict:
    """Fetch (and cache) the provider's JWKS document. Raises on network error."""
    now = time.time()
    cached = _jwks_cache.get(provider)
    if cached and now - cached[0] < _JWKS_CACHE_SECONDS:
        return cached[1]
    url = _resolve(PROVIDERS[provider]["jwks"])
    resp = requests.get(url, timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()
    jwks = resp.json()
    _jwks_cache[provider] = (now, jwks)
    return jwks


def exchange_code(provider: str, code: str) -> dict:
    """Exchange an authorization code for tokens. Raises on network error."""
    meta = PROVIDERS[provider]
    resp = requests.post(
        _resolve(meta["token"]),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_url(provider),
            "client_id": _client_id(provider),
            "client_secret": _client_secret(provider),
        },
        headers={"Accept": "application/json"},
        timeout=_HTTP_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def verify_id_token(provider: str, id_token: str, nonce: str | None = None) -> dict:
    """Verify an id_token's signature (against JWKS), aud, exp and issuer.

    Returns the verified claims. Raises on any verification failure.
    """
    from jose import jwt as _jose_jwt

    meta = PROVIDERS[provider]
    jwks = fetch_jwks(provider)
    # jose selects the matching JWK by the token's kid and verifies the sig.
    claims = _jose_jwt.decode(
        id_token,
        jwks,
        algorithms=["RS256"],
        audience=_client_id(provider),
        options={"verify_at_hash": False},
    )
    # Issuer: Google is fixed; Microsoft embeds the tenant GUID (tid).
    expected_issuer = meta["issuer"]
    if "{tid}" in expected_issuer:
        tid = claims.get("tid", "")
        expected_issuer = expected_issuer.format(tid=tid)
    if claims.get("iss") != expected_issuer:
        raise ValueError(f"issuer mismatch: {claims.get('iss')!r}")
    if nonce and claims.get("nonce") and claims.get("nonce") != nonce:
        raise ValueError("nonce mismatch")
    return claims


# ── Redirect helpers ─────────────────────────────────────────────────────────


def _login_redirect(fragment: str) -> RedirectResponse:
    """307-redirect to the Login page with a #fragment (token or error)."""
    base = _sso_conf()["redirect_base"] or ""
    return RedirectResponse(url=f"{base}/login#{fragment}", status_code=307)


def _error_redirect(reason: str) -> RedirectResponse:
    return _login_redirect(f"sso_error={urllib.parse.quote(reason)}")


# ── Routes ───────────────────────────────────────────────────────────────────


@router.get("/providers")
def list_sso_providers() -> dict:
    """PUBLIC. The Login page calls this to decide which SSO buttons to show."""
    return {"providers": enabled_providers()}


@router.get("/{provider}/login")
def sso_login(provider: str) -> RedirectResponse:
    """PUBLIC. 307-redirect the browser to the provider's authorize page."""
    if provider not in PROVIDERS:
        return _error_redirect("unknown_provider")
    if not is_configured(provider):
        return _error_redirect("provider_not_configured")
    if not _sso_conf()["redirect_base"]:
        return _error_redirect("sso_not_configured")
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    try:
        _store_state(state, provider, nonce)
    except Exception:
        logger.exception("SSO: failed to store state in Redis")
        return _error_redirect("state_store_failed")
    url = build_authorize_url(provider, state, nonce)
    return RedirectResponse(url=url, status_code=307)


@router.get("/{provider}/callback")
def sso_callback(
    provider: str,
    request: Request,
    code: str = "",
    state: str = "",
    error: str = "",
) -> RedirectResponse:
    """PUBLIC. Provider redirects here; we mint a Citadel JWT and bounce to /login."""
    if error:
        return _error_redirect(error)
    if provider not in PROVIDERS or not is_configured(provider):
        return _error_redirect("provider_not_configured")
    if not code:
        return _error_redirect("missing_code")

    # 1. Validate + consume the CSRF state (one-time).
    try:
        consumed = _consume_state(state)
    except Exception:
        logger.exception("SSO: state lookup failed")
        return _error_redirect("state_error")
    if not consumed:
        return _error_redirect("invalid_state")
    state_provider, nonce = consumed
    if state_provider != provider:
        return _error_redirect("state_provider_mismatch")

    # 2. Exchange the code for tokens + verify the id_token.
    try:
        tokens = exchange_code(provider, code)
        id_token = tokens.get("id_token")
        if not id_token:
            return _error_redirect("no_id_token")
        claims = verify_id_token(provider, id_token, nonce=nonce)
    except requests.RequestException:
        logger.exception("SSO: token exchange / JWKS network error")
        return _error_redirect("provider_unreachable")
    except Exception:
        logger.exception("SSO: id_token verification failed")
        return _error_redirect("token_verification_failed")

    # 3. Extract the verified email (+ name) and enforce the allowlist.
    email = (claims.get("email") or claims.get("preferred_username") or "").lower()
    name = claims.get("name") or ""
    if not email:
        return _error_redirect("no_email")
    if not email_allowed(email):
        return _error_redirect("domain_not_allowed")

    # 4. Find-or-provision the Citadel user.
    try:
        ok = provision_user(email, name, provider)
    except Exception:
        logger.exception("SSO: user provisioning failed")
        return _error_redirect("provisioning_failed")
    if not ok:
        return _error_redirect("user_not_provisioned")

    # 5. Mint a Citadel JWT and bounce back to the Login page via fragment.
    try:
        user = service.get_user(email) or {}
        role = user.get("role", _sso_conf()["default_role"])
        jwt_token = service.create_token(email, role)
    except Exception:
        logger.exception("SSO: token minting failed")
        return _error_redirect("token_mint_failed")
    return _login_redirect(f"sso_token={urllib.parse.quote(jwt_token)}")


# ── Admin config endpoints (Redis-backed, secret-redacted) ────────────────────
#
# Mirrors the llm_config /admin/llm-config GET/PUT convention: secrets are
# redacted on GET (replaced by a *_set boolean), and a blank/absent secret on
# PUT preserves the previously stored value (merge-on-blank).


class SSOConfigIn(BaseModel):
    google_client_id: str = ""
    google_client_secret: str = ""  # blank/absent → keep existing
    microsoft_client_id: str = ""
    microsoft_client_secret: str = ""  # blank/absent → keep existing
    microsoft_tenant: str = "common"
    redirect_base: str = ""
    allowed_domains: list[str] = []
    default_role: str = "analyst"
    auto_provision: bool = True


def _config_out(conf: dict) -> dict:
    """Build the redacted GET payload from a merged/effective config dict."""
    base = (conf.get("redirect_base") or "").rstrip("/")
    return {
        "google_client_id": conf.get("google_client_id", ""),
        "google_secret_set": bool(conf.get("google_client_secret")),
        "microsoft_client_id": conf.get("microsoft_client_id", ""),
        "microsoft_secret_set": bool(conf.get("microsoft_client_secret")),
        "microsoft_tenant": conf.get("microsoft_tenant", "common"),
        "redirect_base": base,
        "allowed_domains": conf.get("allowed_domains", []),
        "default_role": conf.get("default_role", "analyst"),
        "auto_provision": bool(conf.get("auto_provision", True)),
        # Hint so the admin knows the redirect_uri to register with each provider.
        "callback_base": {
            "google": f"{base}/api/v1/auth/sso/google/callback",
            "microsoft": f"{base}/api/v1/auth/sso/microsoft/callback",
        },
    }


@admin_router.get("/admin/sso-config", dependencies=_admin_dep)
def get_sso_config() -> dict:
    """Return the effective SSO config (Redis-over-env), secrets REDACTED."""
    return _config_out(_sso_conf())


@admin_router.put("/admin/sso-config", dependencies=_admin_dep)
def update_sso_config(body: SSOConfigIn) -> dict:
    """Persist the SSO config to Redis. Blank secrets preserve the stored value."""
    if body.default_role not in _VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"default_role must be one of {', '.join(_VALID_ROLES)}",
        )

    existing = _stored_conf()
    cfg = {
        "google_client_id": body.google_client_id,
        # Merge-on-blank: keep existing secret if the new request omits it.
        "google_client_secret": body.google_client_secret
        or existing.get("google_client_secret", ""),
        "microsoft_client_id": body.microsoft_client_id,
        "microsoft_client_secret": body.microsoft_client_secret
        or existing.get("microsoft_client_secret", ""),
        "microsoft_tenant": body.microsoft_tenant or "common",
        "redirect_base": (body.redirect_base or "").rstrip("/"),
        "allowed_domains": [d.strip().lower() for d in body.allowed_domains if d and d.strip()],
        "default_role": body.default_role,
        "auto_provision": bool(body.auto_provision),
    }
    _get_redis().set(rk.SSO_CONFIG, json.dumps(cfg))
    return _config_out(_sso_conf())
