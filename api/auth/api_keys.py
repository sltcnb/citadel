"""Personal API keys — long-lived credentials for scripts and external tools.

A key is ``cit_<id>_<secret>``. Only a SHA-256 of the full key is stored (the
secret is 256 bits of randomness, so a slow hash buys nothing); the plaintext
is shown once at creation. A key acts as its owner: every request resolves the
owner's CURRENT user record, so role, group and company changes apply to the
key immediately, and deleting the user kills the key. A password change or an
admin "revoke sessions" (tokens_valid_after) also kills keys created before it,
so a key minted with a stolen password does not outlive the reset.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Optional

import redis_keys as rk

from auth.service import get_user, tokens_valid_for_user
from config import get_redis as _redis

API_KEY_PREFIX = "cit_"
MAX_KEYS_PER_USER = 25
# last_used is informational; write it at most once a minute per key.
_LAST_USED_THROTTLE = 60


def is_api_key(token: str | None) -> bool:
    return bool(token) and token.startswith(API_KEY_PREFIX)


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _public(key_id: str, data: dict) -> dict:
    return {
        "id": key_id,
        "name": data.get("name", ""),
        "prefix": f"{API_KEY_PREFIX}{key_id}_…",
        "created_at": float(data.get("created_at") or 0),
        "expires_at": float(data["expires_at"]) if data.get("expires_at") else None,
        "last_used_at": float(data["last_used_at"]) if data.get("last_used_at") else None,
    }


def create_api_key(username: str, name: str, expires_in_days: int | None = None) -> dict:
    """Mint a key for ``username``. Returns its public metadata plus ``key``
    (the plaintext — never retrievable again)."""
    r = _redis()
    if r.scard(rk.user_api_keys(username)) >= MAX_KEYS_PER_USER:
        raise ValueError(f"API key limit reached ({MAX_KEYS_PER_USER}) — revoke an unused key first")
    key_id = secrets.token_hex(6)
    key = f"{API_KEY_PREFIX}{key_id}_{secrets.token_urlsafe(32)}"
    now = time.time()
    data = {"username": username, "name": name, "hash": _hash(key), "created_at": repr(now)}
    if expires_in_days:
        data["expires_at"] = repr(now + expires_in_days * 86400)
    r.hset(rk.api_key(key_id), mapping=data)
    r.sadd(rk.user_api_keys(username), key_id)
    return {**_public(key_id, data), "key": key}


def list_api_keys(username: str) -> list[dict]:
    r = _redis()
    out = []
    for key_id in r.smembers(rk.user_api_keys(username)):
        data = r.hgetall(rk.api_key(key_id))
        if data:
            out.append(_public(key_id, data))
        else:
            r.srem(rk.user_api_keys(username), key_id)  # dangling index entry
    return sorted(out, key=lambda k: k["created_at"], reverse=True)


def revoke_api_key(username: str, key_id: str) -> bool:
    r = _redis()
    if r.hget(rk.api_key(key_id), "username") != username:
        return False
    r.delete(rk.api_key(key_id))
    r.srem(rk.user_api_keys(username), key_id)
    return True


def resolve_api_key(key: str) -> Optional[dict]:
    """Return the owner's user dict for a valid key, else None. The dict carries
    ``_api_key_id`` so routes can tell key auth from an interactive session."""
    parts = key[len(API_KEY_PREFIX):].split("_", 1) if is_api_key(key) else []
    if len(parts) != 2:
        return None
    key_id = parts[0]
    r = _redis()
    data = r.hgetall(rk.api_key(key_id))
    if not data or not hmac.compare_digest(data.get("hash", ""), _hash(key)):
        return None
    now = time.time()
    if data.get("expires_at") and float(data["expires_at"]) <= now:
        return None
    user = get_user(data.get("username", ""))
    if not user or not tokens_valid_for_user(user, {"iat": data.get("created_at")}):
        return None
    if r.set(rk.api_key_touch(key_id), "1", nx=True, ex=_LAST_USED_THROTTLE):
        r.hset(rk.api_key(key_id), "last_used_at", repr(now))
    user["_api_key_id"] = key_id
    return user
