"""Personal API keys: a key acts as its owner on every API route, and dies with
revocation, expiry, a password reset or the owner's deletion.

Uses the fakeredis `fake_redis` fixture from api/conftest.py.
"""

import asyncio
import sys
import time
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auth import api_keys as ak  # noqa: E402
from auth import service as svc  # noqa: E402
from auth.dependencies import get_current_user, require_upload_access  # noqa: E402


class _Req:
    def __init__(self, query=None):
        self.query_params = query or {}


def _auth(key):
    return asyncio.run(get_current_user(_Req(), key))


def test_key_authenticates_as_its_owner(fake_redis):
    svc.create_user("bot", "pw12345!", role="analyst")
    created = ak.create_api_key("bot", "ci")
    assert created["key"].startswith("cit_")
    user = _auth(created["key"])
    assert user["username"] == "bot" and user["role"] == "analyst"
    assert user["_api_key_id"] == created["id"]


def test_key_in_query_param_works_for_downloads(fake_redis):
    svc.create_user("bot", "pw12345!", role="analyst")
    key = ak.create_api_key("bot", "ci")["key"]
    user = asyncio.run(get_current_user(_Req({"_token": key}), None))
    assert user["username"] == "bot"


def test_plaintext_is_never_stored_or_listed(fake_redis):
    svc.create_user("bot", "pw12345!", role="analyst")
    key = ak.create_api_key("bot", "ci")["key"]
    dump = str({k: fake_redis.hgetall(k) for k in fake_redis.keys("fo:apikey:*") if fake_redis.type(k) == "hash"})
    assert key not in dump
    listed = ak.list_api_keys("bot")
    assert len(listed) == 1 and "key" not in listed[0] and "hash" not in listed[0]


@pytest.mark.parametrize("mangle", [
    lambda k: k[:-1] + ("A" if k[-1] != "A" else "B"),  # wrong secret
    lambda k: "cit_deadbeef0000_" + k.split("_", 2)[2],  # unknown id
    lambda k: "cit_garbage",                             # malformed
])
def test_wrong_keys_are_rejected(fake_redis, mangle):
    svc.create_user("bot", "pw12345!", role="analyst")
    key = ak.create_api_key("bot", "ci")["key"]
    with pytest.raises(HTTPException) as exc:
        _auth(mangle(key))
    assert exc.value.status_code == 401


def test_revoked_key_stops_working_immediately(fake_redis):
    svc.create_user("bot", "pw12345!", role="analyst")
    created = ak.create_api_key("bot", "ci")
    _auth(created["key"])
    assert ak.revoke_api_key("bot", created["id"])
    with pytest.raises(HTTPException):
        _auth(created["key"])


def test_only_the_owner_can_revoke(fake_redis):
    svc.create_user("bot", "pw12345!", role="analyst")
    svc.create_user("eve", "pw12345!", role="analyst")
    created = ak.create_api_key("bot", "ci")
    assert not ak.revoke_api_key("eve", created["id"])
    assert _auth(created["key"])["username"] == "bot"


def test_expired_key_is_rejected(fake_redis):
    svc.create_user("bot", "pw12345!", role="analyst")
    created = ak.create_api_key("bot", "ci", expires_in_days=1)
    fake_redis.hset(ak.rk.api_key(created["id"]), "expires_at", repr(time.time() - 1))
    with pytest.raises(HTTPException):
        _auth(created["key"])


def test_password_reset_kills_older_keys(fake_redis):
    svc.create_user("bot", "pw12345!", role="analyst")
    key = ak.create_api_key("bot", "ci")["key"]
    time.sleep(0.01)
    svc.revoke_user_tokens("bot")
    with pytest.raises(HTTPException):
        _auth(key)


def test_recreating_a_deleted_user_does_not_revive_keys(fake_redis):
    svc.create_user("bot", "pw12345!", role="analyst")
    key = ak.create_api_key("bot", "ci")["key"]
    svc.delete_user("bot")
    svc.create_user("bot", "pw12345!", role="analyst")
    with pytest.raises(HTTPException):
        _auth(key)


def test_role_change_kills_keys_like_sessions(fake_redis):
    svc.create_user("bot", "pw12345!", role="analyst")
    key = ak.create_api_key("bot", "ci")["key"]
    time.sleep(0.01)
    svc.change_role("bot", "guest")
    with pytest.raises(HTTPException):
        _auth(key)
    assert _auth(ak.create_api_key("bot", "ci2")["key"])["role"] == "guest"


def test_key_can_upload_to_own_company_case_only(fake_redis):
    svc.create_user("bot", "pw12345!", role="analyst", companies=["Acme"])
    for cid, company in (("c1", "Acme"), ("c2", "Other")):
        fake_redis.hset(f"case:{cid}", mapping={"case_id": cid, "name": "T", "company": company})
        fake_redis.sadd("cases:all", cid)
    key = ak.create_api_key("bot", "ci")["key"]
    assert require_upload_access("c1", _Req(), key)["case_id"] == "c1"
    with pytest.raises(HTTPException) as exc:
        require_upload_access("c2", _Req(), key)
    assert exc.value.status_code == 403


def test_a_key_cannot_mint_more_keys(fake_redis):
    from routers.auth import ApiKeyCreateRequest, api_keys_create

    svc.create_user("bot", "pw12345!", role="analyst")
    user = _auth(ak.create_api_key("bot", "ci")["key"])
    with pytest.raises(HTTPException) as exc:
        asyncio.run(api_keys_create(ApiKeyCreateRequest(name="more"), user))
    assert exc.value.status_code == 403


def test_per_user_key_limit(fake_redis):
    svc.create_user("bot", "pw12345!", role="analyst")
    for i in range(ak.MAX_KEYS_PER_USER):
        ak.create_api_key("bot", f"k{i}")
    with pytest.raises(ValueError):
        ak.create_api_key("bot", "one-too-many")
