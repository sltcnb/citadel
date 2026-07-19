"""Regression test for the /auth/login rate-limit bypass via forged
X-Forwarded-For (P0).

nginx (nginx/nginx.prod.conf) sets
``proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for``, which
APPENDS the peer it saw to whatever XFF value the client sent -- so the
header is shaped like ``"<attacker-controlled>, <ip nginx saw>"``. Keying the
login rate limit off the *first* (leftmost) XFF entry let an attacker forge a
brand-new value on every request and get a fresh Redis bucket each time,
brute-forcing /auth/login without ever being throttled.

These tests prove that two requests differing ONLY in a forged first XFF hop
land in the SAME rate-limit bucket -- the exploit no longer works -- while
normal (no-proxy / single-hop) traffic is still keyed correctly.
"""

import sys
from pathlib import Path

import fakeredis
import pytest
from fastapi import HTTPException, Request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import redis_keys as rk  # noqa: E402

import routers.auth as auth_router  # noqa: E402
import routers.platform_settings as ps  # noqa: E402


@pytest.fixture
def fake_redis(monkeypatch):
    fake = fakeredis.FakeRedis(decode_responses=True)
    # _check_login_rate_limit reads Redis directly for the counter...
    monkeypatch.setattr(auth_router, "_get_redis", lambda: fake, raising=True)
    # ...and also lazily calls routers.platform_settings.get_platform_config(),
    # which reads its own Redis handle for the (unset) admin overrides.
    monkeypatch.setattr(ps, "_redis", lambda: fake, raising=True)
    return fake


def _request(xff: str | None, peer: str = "10.0.0.9") -> Request:
    """Build a real fastapi.Request carrying the given X-Forwarded-For value
    and a fixed direct TCP peer (standing in for the nginx <-> uvicorn hop)."""
    headers = [(b"x-forwarded-for", xff.encode())] if xff is not None else []
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/auth/login",
        "headers": headers,
        "client": (peer, 51234),
    }
    return Request(scope)


def test_forged_first_hop_cannot_mint_a_fresh_bucket(fake_redis, monkeypatch):
    """A brand-new, attacker-chosen first XFF entry on every request must
    still be counted against the SAME bucket as the real peer -- proving the
    fresh-bucket-per-request bypass is closed."""
    monkeypatch.setattr(auth_router.settings, "TRUSTED_PROXY_HOPS", 1, raising=False)

    req_a = _request("203.0.113.1, 10.0.0.9")  # forged hop, attempt A
    req_b = _request("198.51.100.77, 10.0.0.9")  # different forged hop, attempt B

    for _ in range(5):
        auth_router._check_login_rate_limit(req_a)
        auth_router._check_login_rate_limit(req_b)

    key = rk.login_ratelimit("10.0.0.9")
    # All 10 attempts (5 x each forged identity) landed in the one real-peer bucket.
    assert fake_redis.get(key) == "10"


def test_forged_first_hop_still_gets_rate_limited(fake_redis, monkeypatch):
    """Even with a fresh forged IP on every single request, the shared bucket
    still trips the configured limit -- brute-forcing is throttled again."""
    monkeypatch.setattr(auth_router.settings, "TRUSTED_PROXY_HOPS", 1, raising=False)
    monkeypatch.setattr(
        ps,
        "get_platform_config",
        lambda: {"login_rate_limit": 3, "login_rate_window_seconds": 60},
    )

    forged_attempts = [_request(f"{i}.{i}.{i}.{i}, 10.0.0.9") for i in range(10)]
    allowed = 0
    with pytest.raises(HTTPException) as exc_info:
        for req in forged_attempts:
            auth_router._check_login_rate_limit(req)
            allowed += 1

    assert exc_info.value.status_code == 429
    assert allowed == 3  # limit enforced across the shared bucket, not per forged IP


def test_resolve_client_ip_trusts_only_the_configured_proxy_hops():
    resolve = auth_router._resolve_client_ip

    # Single trusted nginx hop: only the rightmost (nginx-appended) entry counts.
    assert resolve("1.2.3.4, 10.0.0.9", "10.0.0.9", 1) == "10.0.0.9"
    # Any amount of attacker-forged padding to the left is still ignored.
    assert resolve("6.6.6.6, 5.5.5.5, 9.9.9.9, 10.0.0.9", "10.0.0.9", 1) == "10.0.0.9"
    # No proxy in front of the API (trusted_hops=0): header must be ignored entirely.
    assert resolve("1.2.3.4", "10.0.0.9", 0) == "10.0.0.9"
    # No XFF header at all: fall back to the direct TCP peer.
    assert resolve(None, "10.0.0.9", 1) == "10.0.0.9"
    # Fewer hops present than configured (misconfigured/truncated proxy chain):
    # fail closed to the direct peer rather than trust client-controlled data.
    assert resolve("1.2.3.4", "10.0.0.9", 2) == "10.0.0.9"
