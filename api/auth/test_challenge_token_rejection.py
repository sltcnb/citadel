"""Regression tests: MFA / forced-password-change challenge tokens must be
rejected by get_current_user — they prove one login step passed, not API access.

Previously these tokens were signed with the same JWT_SECRET as access tokens
and accepted everywhere, so a stolen password alone bypassed TOTP, and the
default admin's forced password change could be skipped by using the returned
pw_token directly as a Bearer token.

Uses the fakeredis `fake_redis` fixture from api/conftest.py.
"""

import asyncio
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auth import service as svc  # noqa: E402
from auth.dependencies import get_current_user  # noqa: E402


class _Req:
    """Minimal Request stand-in: get_current_user only reads query_params."""

    def __init__(self):
        self.query_params = {}


def _call(token):
    return asyncio.run(get_current_user(_Req(), token))


def test_mfa_challenge_token_rejected(fake_redis):
    svc.create_user("mallory", "pw123!", role="admin")
    challenge = svc.create_mfa_challenge("mallory")
    with pytest.raises(HTTPException) as exc:
        _call(challenge)
    assert exc.value.status_code == 401


def test_pw_change_challenge_token_rejected(fake_redis):
    svc.create_user("admin", "CitadelAdmin1!", role="admin")
    challenge = svc.create_pw_change_challenge("admin")
    with pytest.raises(HTTPException) as exc:
        _call(challenge)
    assert exc.value.status_code == 401


def test_challenge_rejected_with_warm_cache(fake_redis):
    # Warm the identity cache with a genuine access token, then confirm a
    # challenge token still 401s — the guard must also run on the cache path.
    svc.create_user("erin", "pw123!", role="analyst")
    access = svc.create_token("erin", "analyst")
    assert _call(access)["username"] == "erin"
    with pytest.raises(HTTPException) as exc:
        _call(svc.create_mfa_challenge("erin"))
    assert exc.value.status_code == 401


def test_access_token_still_accepted(fake_redis):
    svc.create_user("dave", "pw123!", role="analyst")
    user = _call(svc.create_token("dave", "analyst"))
    assert user["username"] == "dave"
    assert user["role"] == "analyst"


def test_stream_token_still_accepted(fake_redis):
    # 60s stream tokens legitimately authorize downloads/SSE — the challenge
    # guard must not break them.
    svc.create_user("sam", "pw123!", role="developer")
    assert _call(svc.create_stream_token("sam", "developer"))["username"] == "sam"
