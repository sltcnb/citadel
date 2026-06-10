"""Authentication service — JWT + bcrypt, users stored in Redis."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta

import redis_keys as rk
from jose import jwt
from passlib.context import CryptContext

from config import get_redis as _redis
from config import settings

logger = logging.getLogger(__name__)

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Keep module-level aliases so external importers (main.py) don't break.
_USERS_SET = rk.USERS_SET
_USER_KEY = "fo:user:{username}"


# ── Password helpers ──────────────────────────────────────────────────────────


def hash_password(password: str) -> str:
    return _pwd_ctx.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


# ── JWT helpers ───────────────────────────────────────────────────────────────


def create_token(username: str, role: str) -> str:
    expire = datetime.now(UTC) + timedelta(hours=settings.JWT_EXPIRE_HOURS)
    payload = {"sub": username, "role": role, "exp": expire, "jti": str(uuid.uuid4())}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and verify JWT. Raises JWTError on failure."""
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])


def revoke_token(token: str) -> None:
    """Add a token to the revocation list (stored in Redis until natural expiry)."""
    try:
        payload = decode_token(token)
        jti = payload.get("jti")
        if not jti:
            return
        exp = payload.get("exp")
        now = datetime.now(UTC).timestamp()
        ttl = max(1, int(exp - now)) if exp else settings.JWT_EXPIRE_HOURS * 3600
        _redis().setex(rk.jwt_revoked(jti), ttl, "1")
    except Exception:
        pass


def is_token_revoked(payload: dict) -> bool:
    """Return True if the token's jti has been revoked."""
    jti = payload.get("jti")
    if not jti:
        return False
    try:
        return bool(_redis().exists(rk.jwt_revoked(jti)))
    except Exception:
        return False


# ── User CRUD (Redis-backed) ──────────────────────────────────────────────────


def get_user(username: str) -> Optional[dict]:
    r = _redis()
    data = r.hgetall(rk.user_key(username))
    return data or None


def authenticate(username: str, password: str) -> Optional[dict]:
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user.get("hashed_password", "")):
        return None
    return user


VALID_ROLES = ("admin", "analyst", "developer", "guest")


def create_user(
    username: str, password: str, role: str = "analyst", companies: list[str] | None = None
) -> dict:
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role '{role}'. Must be one of: {', '.join(VALID_ROLES)}")
    r = _redis()
    key = rk.user_key(username)
    if r.exists(key):
        raise ValueError(f"User '{username}' already exists")
    user = {
        "username": username,
        "hashed_password": hash_password(password),
        "role": role,
        "companies": json.dumps(companies or []),
        "created_at": datetime.now(UTC).isoformat(),
    }
    r.hset(key, mapping=user)
    r.sadd(_USERS_SET, username)
    return _public(user)


def delete_user(username: str) -> bool:
    r = _redis()
    key = rk.user_key(username)
    if not r.exists(key):
        return False
    r.delete(key)
    r.srem(_USERS_SET, username)
    return True


def list_users() -> list[dict]:
    r = _redis()
    usernames = r.smembers(_USERS_SET)
    users = []
    for u in sorted(usernames):
        user = r.hgetall(rk.user_key(u))
        if user:
            users.append(_public(user))
    return users


def update_user(
    username: str,
    role: Optional[str] = None,
    password: Optional[str] = None,
    companies: Optional[list[str]] = None,
) -> dict:
    """Update a user's role, password, and/or company restrictions."""
    r = _redis()
    key = rk.user_key(username)
    if not r.exists(key):
        raise ValueError(f"User '{username}' not found")
    if role is not None:
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role '{role}'. Must be one of: {', '.join(VALID_ROLES)}")
        r.hset(key, "role", role)
    if password is not None:
        r.hset(key, "hashed_password", hash_password(password))
    if companies is not None:
        r.hset(key, "companies", json.dumps(companies))
    return _public(r.hgetall(key))


def update_password(username: str, new_password: str) -> bool:
    r = _redis()
    key = rk.user_key(username)
    if not r.exists(key):
        return False
    r.hset(key, "hashed_password", hash_password(new_password))
    return True


def change_role(username: str, new_role: str) -> bool:
    r = _redis()
    key = rk.user_key(username)
    if not r.exists(key):
        return False
    r.hset(key, "role", new_role)
    return True


def user_count() -> int:
    return _redis().scard(_USERS_SET)


def _public(user: dict) -> dict:
    """Strip hashed_password; parse companies JSON before returning."""
    result = {k: v for k, v in user.items() if k != "hashed_password"}
    if "companies" in result:
        try:
            result["companies"] = json.loads(result["companies"])
        except (json.JSONDecodeError, TypeError):
            result["companies"] = []
    else:
        result["companies"] = []
    return result
