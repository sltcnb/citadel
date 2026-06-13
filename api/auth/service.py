"""Authentication service — JWT + bcrypt, users stored in Redis."""

from __future__ import annotations

import json
import logging
import secrets
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


def create_stream_token(username: str, role: str) -> str:
    """Mint a SHORT-LIVED (60s) access token for SSE/EventSource streams.

    EventSource cannot set an Authorization header, so the token rides in the
    ``?_token=`` query param — which then leaks into proxy/server logs and
    browser history. Issuing a 60-second token instead of the full 8-hour access
    JWT bounds that exposure. It carries the same claims as a normal access token
    (sub, role, jti), so decode_token / get_current_user accept it as-is."""
    expire = datetime.now(UTC) + timedelta(seconds=60)
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


# ── Forced password change ──────────────────────────────────────────────────
# A user flagged must_change_password cannot obtain a full access token until
# they rotate their password. Used to retire the default bootstrap-admin
# password (and reusable for admin-provisioned "change on first login").


def must_change_password(username: str) -> bool:
    u = get_user(username)
    return bool(u and u.get("must_change_password") == "1")


def set_must_change_password(username: str, value: bool = True) -> None:
    r = _redis()
    key = rk.user_key(username)
    if value:
        r.hset(key, "must_change_password", "1")
    else:
        r.hdel(key, "must_change_password")


def create_pw_change_challenge(username: str) -> str:
    """Short-lived token proving the password step passed; only usable to set a
    new password (NOT an access token)."""
    expire = datetime.now(UTC) + timedelta(minutes=_MFA_CHALLENGE_MINUTES)
    payload = {"sub": username, "pwc": True, "exp": expire, "jti": str(uuid.uuid4())}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_pw_change_challenge(token: str) -> Optional[str]:
    """Return the username if ``token`` is a valid password-change challenge."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except Exception:
        return None
    if payload.get("pwc") and payload.get("sub"):
        return payload["sub"]
    return None


# ── MFA / TOTP ─────────────────────────────────────────────────────────────────
#
# Login is two-step when a user has TOTP enabled: password is checked first; on
# success the server issues a short-lived "MFA challenge" token (it is NOT an
# access token — it only proves the password step passed). The client then posts
# the 6-digit code (or a one-time backup code) with that challenge to finish.

_TOTP_ISSUER = "Citadel"
_MFA_CHALLENGE_MINUTES = 5
_BACKUP_CODE_COUNT = 10


def create_mfa_challenge(username: str) -> str:
    """Short-lived token proving the password step passed (not an access token)."""
    expire = datetime.now(UTC) + timedelta(minutes=_MFA_CHALLENGE_MINUTES)
    payload = {"sub": username, "mfa": True, "exp": expire, "jti": str(uuid.uuid4())}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_mfa_challenge(token: str) -> Optional[str]:
    """Return the username if ``token`` is a valid MFA challenge, else None."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except Exception:
        return None
    if payload.get("mfa") and payload.get("sub"):
        return payload["sub"]
    return None


def is_totp_enabled(username: str) -> bool:
    u = get_user(username)
    return bool(u and u.get("totp_enabled") == "1")


def start_totp_enrollment(username: str) -> dict:
    """Generate a pending secret + provisioning URI for QR enrollment.

    The secret is stored as *pending* and only promoted to active once the user
    proves they can produce a valid code (confirm_totp_enrollment).
    """
    import pyotp

    secret = pyotp.random_base32()
    _redis().hset(rk.user_key(username), "totp_pending_secret", secret)
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=_TOTP_ISSUER)
    return {"secret": secret, "otpauth_uri": uri}


def confirm_totp_enrollment(username: str, code: str) -> Optional[list[str]]:
    """Verify the pending secret with ``code``; on success activate TOTP and
    return freshly generated one-time backup codes (shown to the user once)."""
    import pyotp

    u = get_user(username)
    secret = (u or {}).get("totp_pending_secret")
    if not secret:
        return None
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return None
    codes = [_gen_backup_code() for _ in range(_BACKUP_CODE_COUNT)]
    hashes = [hash_password(c.replace("-", "")) for c in codes]
    key = rk.user_key(username)
    r = _redis()
    r.hset(key, mapping={
        "totp_secret": secret,
        "totp_enabled": "1",
        "totp_backup": json.dumps(hashes),
    })
    r.hdel(key, "totp_pending_secret")
    return codes


def verify_totp(username: str, code: str) -> bool:
    """Accept a current TOTP code OR a one-time backup code (consumed on use)."""
    import pyotp

    u = get_user(username)
    if not u or u.get("totp_enabled") != "1":
        return False
    secret = u.get("totp_secret", "")
    code = (code or "").strip()
    if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
        return True
    return _consume_backup_code(username, code, u)


def _consume_backup_code(username: str, code: str, user: dict) -> bool:
    norm = code.replace("-", "").replace(" ", "")
    try:
        hashes = json.loads(user.get("totp_backup") or "[]")
    except (json.JSONDecodeError, TypeError):
        hashes = []
    for h in list(hashes):
        try:
            if verify_password(norm, h):
                hashes.remove(h)
                _redis().hset(rk.user_key(username), "totp_backup", json.dumps(hashes))
                return True
        except Exception:
            continue
    return False


def disable_totp(username: str) -> bool:
    r = _redis()
    key = rk.user_key(username)
    if not r.exists(key):
        return False
    r.hdel(key, "totp_secret", "totp_enabled", "totp_backup", "totp_pending_secret")
    return True


def backup_codes_remaining(username: str) -> int:
    u = get_user(username)
    try:
        return len(json.loads((u or {}).get("totp_backup") or "[]"))
    except (json.JSONDecodeError, TypeError):
        return 0


def _gen_backup_code() -> str:
    raw = secrets.token_hex(4)  # 8 hex chars
    return f"{raw[:4]}-{raw[4:]}"


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
        r.hdel(key, "must_change_password")  # rotating the password clears the force-change flag
    if companies is not None:
        r.hset(key, "companies", json.dumps(companies))
    return _public(r.hgetall(key))


def update_password(username: str, new_password: str) -> bool:
    r = _redis()
    key = rk.user_key(username)
    if not r.exists(key):
        return False
    r.hset(key, "hashed_password", hash_password(new_password))
    r.hdel(key, "must_change_password")
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


_SECRET_FIELDS = {"hashed_password", "totp_secret", "totp_pending_secret", "totp_backup"}


def _public(user: dict) -> dict:
    """Strip secrets (password hash, TOTP secret, backup codes); parse companies."""
    result = {k: v for k, v in user.items() if k not in _SECRET_FIELDS}
    if "companies" in result:
        try:
            result["companies"] = json.loads(result["companies"])
        except (json.JSONDecodeError, TypeError):
            result["companies"] = []
    else:
        result["companies"] = []
    return result
