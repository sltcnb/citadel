"""Authentication service — JWT + bcrypt, users stored in Redis."""

from __future__ import annotations

import json
import logging
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Optional

import bcrypt
import redis_keys as rk
from jose import jwt
from services.redis_mutate import mutate_json

from auth import rbac
from config import get_redis as _redis
from config import settings

logger = logging.getLogger(__name__)

# Keep module-level aliases so external importers (main.py) don't break.
_USERS_SET = rk.USERS_SET
_USER_KEY = "fo:user:{username}"
# Single JSON document {group_id: group} holding all RBAC groups.
_GROUPS_KEY = "fo:groups"
# Bumped on every group mutation. auth.dependencies caches resolved permissions
# per token for a few seconds; without a change signal a user kept their old
# effective permissions for the whole cache TTL after being moved between
# groups (or removed from one). Every API worker watches this counter, so the
# invalidation crosses processes — clearing a local dict would only fix the
# worker that happened to serve the write.
_GROUPS_EPOCH_KEY = "fo:groups:epoch"


# ── Password helpers ──────────────────────────────────────────────────────────


def _bcrypt_bytes(password: str) -> bytes:
    """bcrypt uses at most the first 72 bytes of a password. bcrypt 5.x raises on
    longer input instead of truncating, and passlib 1.7.4 is incompatible with
    bcrypt >= 4 (it reads the removed ``bcrypt.__about__``), so we call bcrypt
    directly. Truncating to 72 bytes matches what every previously stored hash
    already encoded, so existing logins keep verifying unchanged."""
    return password.encode("utf-8")[:72]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_bcrypt_bytes(password), bcrypt.gensalt()).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_bcrypt_bytes(plain), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# ── JWT helpers ───────────────────────────────────────────────────────────────


def create_token(username: str, role: str) -> str:
    try:
        from routers.platform_settings import get_platform_config

        hours = int(get_platform_config()["jwt_expire_hours"])
    except Exception:
        hours = settings.JWT_EXPIRE_HOURS
    now = datetime.now(UTC)
    expire = now + timedelta(hours=hours)
    payload = {
        "sub": username,
        "role": role,
        "exp": expire,
        "iat": now.timestamp(),
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    _seed_session_activity(payload)
    return token


def _seed_session_activity(payload: dict) -> None:
    """Start the session-idle clock for a freshly minted access token when the
    ``session_idle_minutes`` platform setting is enabled. Fail-open: a Redis or
    config hiccup at login must not break token creation."""
    try:
        from routers.platform_settings import get_platform_config

        minutes = int(get_platform_config().get("session_idle_minutes") or 0)
        if minutes <= 0:
            return
        jti = payload.get("jti")
        if jti:
            _redis().setex(f"fo:session:active:{jti}", minutes * 60, "1")
    except Exception:
        pass


def create_stream_token(username: str, role: str) -> str:
    """Mint a SHORT-LIVED (60s) access token for SSE/EventSource streams.

    EventSource cannot set an Authorization header, so the token rides in the
    ``?_token=`` query param — which then leaks into proxy/server logs and
    browser history. Issuing a 60-second token instead of the full 8-hour access
    JWT bounds that exposure. It carries the same claims as a normal access token
    (sub, role, jti), so decode_token / get_current_user accept it as-is."""
    expire = datetime.now(UTC) + timedelta(seconds=60)
    payload = {
        "sub": username,
        "role": role,
        "exp": expire,
        "iat": datetime.now(UTC).timestamp(),
        "jti": str(uuid.uuid4()),
    }
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


# ── Per-user token invalidation ───────────────────────────────────────────────
# Revoking every outstanding token for a user (password change, role change)
# cannot enumerate issued jtis, so instead the user record carries a
# ``tokens_valid_after`` epoch timestamp: any token minted BEFORE that instant
# is rejected at validation. Compared as floats (sub-second precision) so a
# token minted in the same second as the change is still correctly invalidated,
# while the fresh token issued right after the change (later timestamp) passes.


def revoke_user_tokens(username: str) -> None:
    """Invalidate every token issued for ``username`` up to now."""
    import time

    _redis().hset(rk.user_key(username), "tokens_valid_after", repr(time.time()))


def tokens_valid_for_user(user: dict, payload: dict) -> bool:
    """True unless the token predates the user's ``tokens_valid_after`` stamp.

    Tokens minted before this mechanism existed carry no ``iat`` — they pass
    while no invalidation was recorded, and are rejected once one is (the user
    simply re-logs-in after a password/role change)."""
    tva = (user or {}).get("tokens_valid_after")
    if not tva:
        return True
    try:
        tva_f = float(tva)
    except (TypeError, ValueError):
        return True
    try:
        iat_f = float(payload.get("iat") or 0)
    except (TypeError, ValueError):
        iat_f = 0.0
    return iat_f >= tva_f


def token_fresh_for_user(username: str, payload: dict) -> bool:
    """Same check as :func:`tokens_valid_for_user` but reads the stamp FRESH
    from Redis (one cheap HGET). Used on the identity-cache hit path, where the
    cached user dict may be up to a few seconds stale — a password/role change
    must invalidate promptly, like jti revocation does. Fails open on Redis
    errors, matching is_token_revoked."""
    if not username:
        return True
    try:
        raw = _redis().hget(rk.user_key(username), "tokens_valid_after")
    except Exception:
        return True
    return tokens_valid_for_user({"tokens_valid_after": raw}, payload)


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
    """Return the username if ``token`` is a valid password-change challenge.

    Challenges are single-use: the jti is revoked on a successful password
    change, and revoked challenges are rejected here."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except Exception:
        return None
    if is_token_revoked(payload):
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
    """Return the username if ``token`` is a valid MFA challenge, else None.

    Challenges are single-use, exactly like password-change challenges: the jti
    is revoked once the TOTP step succeeds, and revoked challenges are rejected
    here. Without that check a captured challenge stayed usable for the whole
    5-minute TTL, so an intercepted token plus any valid code could mint
    further access tokens for the same account."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except Exception:
        return None
    if is_token_revoked(payload):
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
    """Accept a current TOTP code OR a one-time backup code (consumed on use).

    A valid TOTP code stays cryptographically valid for up to ~90s
    (valid_window=1), so a replay cache (Redis, keyed by user+code, 90s TTL)
    rejects a second presentation of the same code within that window. The
    cache fails CLOSED: if replay protection cannot be enforced the code is
    refused. That costs nothing in availability terms — the user records
    themselves live in Redis, so a Redis outage has already stopped every
    login before this point."""
    import pyotp

    u = get_user(username)
    if not u or u.get("totp_enabled") != "1":
        return False
    secret = u.get("totp_secret", "")
    code = (code or "").strip()
    if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
        if not _mark_totp_code_used(username, code):
            return False  # same code already presented within the valid window
        return True
    return _consume_backup_code(username, code, u)


def _mark_totp_code_used(username: str, code: str) -> bool:
    """Atomically claim (user, code) for the TOTP validity window. Returns False
    if the code was already used (replay), or if the claim could not be made.

    Fails CLOSED. Returning True on a Redis error would have made the same
    code reusable for its whole ~90s window during an outage, which is exactly
    the replay this cache exists to stop."""
    key = f"fo:totp:used:{username}:{code}"
    try:
        return bool(_redis().set(key, "1", nx=True, ex=90))
    except Exception as exc:
        logger.error(
            "TOTP replay protection unavailable (%s) — refusing the code for "
            "'%s' rather than accepting one that could be replayed.",
            exc,
            username,
        )
        return False


def _consume_backup_code(username: str, code: str, user: dict) -> bool:
    """Consume a one-time backup code atomically.

    The read-check-remove-write on the ``totp_backup`` JSON list runs under
    WATCH/MULTI so two concurrent logins presenting the SAME code cannot both
    succeed (the loser gets a WatchError, retries against fresh state, and no
    longer finds the code)."""
    from redis import WatchError

    norm = code.replace("-", "").replace(" ", "")
    key = rk.user_key(username)
    r = _redis()
    for _ in range(3):
        with r.pipeline() as pipe:
            try:
                pipe.watch(key)
                raw = pipe.hget(key, "totp_backup")
                try:
                    hashes = json.loads(raw or "[]")
                except (json.JSONDecodeError, TypeError):
                    hashes = []
                match = None
                for h in list(hashes):
                    try:
                        if verify_password(norm, h):
                            match = h
                            break
                    except Exception:
                        continue
                if match is None:
                    return False
                hashes.remove(match)
                pipe.multi()
                pipe.hset(key, "totp_backup", json.dumps(hashes))
                pipe.execute()
                return True
            except WatchError:
                continue  # concurrent mutation — re-read and try again
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
    username: str,
    password: str,
    role: str = "analyst",
    companies: list[str] | None = None,
    groups: list[str] | None = None,
    extra_permissions: list[str] | None = None,
) -> dict:
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role '{role}'. Must be one of: {', '.join(VALID_ROLES)}")
    if not password or not password.strip():
        raise ValueError("Password must not be empty")
    r = _redis()
    key = rk.user_key(username)
    if r.exists(key):
        raise ValueError(f"User '{username}' already exists")
    user = {
        "username": username,
        "hashed_password": hash_password(password),
        "role": role,
        "companies": json.dumps(companies or []),
        "groups": json.dumps(groups or []),
        "extra_permissions": json.dumps(_clean_perms(extra_permissions)),
        "created_at": datetime.now(UTC).isoformat(),
    }
    r.hset(key, mapping=user)
    r.sadd(_USERS_SET, username)
    if groups:
        _sync_group_members_for_user(username, groups)
    return _public(user)


def delete_user(username: str) -> bool:
    r = _redis()
    key = rk.user_key(username)
    if not r.exists(key):
        return False
    r.delete(key)
    r.srem(_USERS_SET, username)
    _sync_group_members_for_user(username, [])  # drop from every group's members
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
    groups: Optional[list[str]] = None,
    extra_permissions: Optional[list[str]] = None,
) -> dict:
    """Update a user's role, password, company restrictions, group memberships
    and/or per-user extra permissions."""
    r = _redis()
    key = rk.user_key(username)
    if not r.exists(key):
        raise ValueError(f"User '{username}' not found")
    credentials_changed = False
    if role is not None:
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role '{role}'. Must be one of: {', '.join(VALID_ROLES)}")
        r.hset(key, "role", role)
        # A role change must take effect immediately: outstanding tokens carry
        # the OLD role claim, so invalidate them — the user re-logs-in.
        credentials_changed = True
    if password is not None:
        r.hset(key, "hashed_password", hash_password(password))
        r.hdel(key, "must_change_password")  # rotating the password clears the force-change flag
        # Invalidate sessions minted under the old (possibly compromised) password.
        credentials_changed = True
    if companies is not None:
        r.hset(key, "companies", json.dumps(companies))
    if groups is not None:
        r.hset(key, "groups", json.dumps(groups))
    if extra_permissions is not None:
        r.hset(key, "extra_permissions", json.dumps(_clean_perms(extra_permissions)))
    if credentials_changed:
        revoke_user_tokens(username)
    if groups is not None:
        _sync_group_members_for_user(username, groups)
    return _public(r.hgetall(key))


def update_password(username: str, new_password: str) -> bool:
    r = _redis()
    key = rk.user_key(username)
    if not r.exists(key):
        return False
    r.hset(key, "hashed_password", hash_password(new_password))
    r.hdel(key, "must_change_password")
    revoke_user_tokens(username)
    return True


def change_role(username: str, new_role: str) -> bool:
    r = _redis()
    key = rk.user_key(username)
    if not r.exists(key):
        return False
    r.hset(key, "role", new_role)
    revoke_user_tokens(username)
    return True


def user_count() -> int:
    return _redis().scard(_USERS_SET)


_SECRET_FIELDS = {"hashed_password", "totp_secret", "totp_pending_secret", "totp_backup"}


def _parse_json_list(result: dict, field: str) -> None:
    """In-place: parse ``result[field]`` (a JSON string from the hash) into a list,
    defaulting to [] on absence or malformed data."""
    raw = result.get(field)
    if raw is None:
        result[field] = []
        return
    try:
        parsed = json.loads(raw)
        result[field] = parsed if isinstance(parsed, list) else []
    except (json.JSONDecodeError, TypeError):
        result[field] = []


def _public(user: dict) -> dict:
    """Strip secrets (password hash, TOTP secret, backup codes); parse the
    JSON-encoded list fields (companies, groups, extra_permissions)."""
    result = {k: v for k, v in user.items() if k not in _SECRET_FIELDS}
    _parse_json_list(result, "companies")
    _parse_json_list(result, "groups")
    _parse_json_list(result, "extra_permissions")
    return result


# ── Permission / id helpers ─────────────────────────────────────────────────────


def _clean_perms(perms: list[str] | None) -> list[str]:
    """Keep only known permission ids, de-duplicated and sorted."""
    if not perms:
        return []
    return sorted({p for p in perms if p in rbac.ALL_PERMISSIONS})


def _slugify(value: str) -> str:
    """Turn a group name into a stable, url-safe id."""
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-")
    return slug or "group"


# ── Group store (Redis-backed JSON at fo:groups) ────────────────────────────────
# A single JSON document {id: group} keyed at _GROUPS_KEY. Group shape:
#   {id, name, description, roles, permissions, companies, members}
# Writes go through mutate_json for atomic read-modify-write under contention.
#
# Membership is recorded in TWO places: ``user["groups"]`` (CANONICAL — this is
# what rbac.effective_permissions / effective_companies enforce) and
# ``group["members"]`` (what the UI's members picker edits and the effective
# view reports). The two are kept in sync by every write path below and by the
# user CRUD above, so editing either side grants/revokes access identically.


def _sync_group_members_for_user(username: str, groups: list[str]) -> None:
    """Make every group's ``members`` list consistent with a user's canonical
    ``groups`` field (add to the listed groups, remove from all others).
    Best-effort: a store failure is logged, never fatal to the user write."""
    wanted = {str(g) for g in (groups or [])}

    def _sync(store: dict) -> dict:
        for gid, g in store.items():
            members = {str(m) for m in (g.get("members") or [])}
            if gid in wanted:
                members.add(username)
            else:
                members.discard(username)
            g["members"] = sorted(members)
        return store

    try:
        mutate_json(_redis(), _GROUPS_KEY, _sync, default={})
    except Exception:
        logger.warning("group members sync failed for user '%s'", username)


def _sync_user_groups_for_members(group_id: str, members: list[str]) -> None:
    """Make the canonical ``user["groups"]`` consistent with a group's edited
    ``members`` list: listed users gain the membership, everyone else loses it.
    Best-effort: a failure is logged, never fatal to the group write."""
    wanted = {str(m) for m in (members or [])}
    try:
        r = _redis()
        for username in r.smembers(_USERS_SET):
            key = rk.user_key(username)
            try:
                groups = set(json.loads(r.hget(key, "groups") or "[]"))
            except (json.JSONDecodeError, TypeError):
                groups = set()
            new = set(groups)
            if username in wanted:
                new.add(group_id)
            else:
                new.discard(group_id)
            if new != groups:
                r.hset(key, "groups", json.dumps(sorted(new)))
    except Exception:
        logger.warning("user groups sync failed for group '%s'", group_id)


def list_groups() -> list[dict]:
    """Return all groups sorted by name."""
    return sorted(groups_index().values(), key=lambda g: g.get("name", g.get("id", "")))


def groups_epoch() -> str:
    """Current group-store generation. "0" if it cannot be read (callers then
    keep their cached value rather than stampeding Redis)."""
    try:
        return str(_redis().get(_GROUPS_EPOCH_KEY) or "0")
    except Exception:
        return "0"


def _bump_groups_epoch() -> None:
    """Invalidate every worker's cached permission resolution."""
    try:
        _redis().incr(_GROUPS_EPOCH_KEY)
    except Exception as exc:
        logger.warning(
            "Could not bump the group epoch (%s) — cached permissions may stay "
            "stale for up to the identity-cache TTL.",
            exc,
        )


def groups_index() -> dict[str, dict]:
    """Return the {group_id: group} map (the raw store document)."""
    r = _redis()
    raw = r.get(_GROUPS_KEY)
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def get_group(group_id: str) -> Optional[dict]:
    return groups_index().get(group_id)


def _normalize_group(group_id: str, name: str, description, roles, permissions,
                     companies, members) -> dict:
    g = rbac.empty_group(group_id, name)
    g["description"] = description or ""
    g["roles"] = sorted({r for r in (roles or []) if r in VALID_ROLES})
    g["permissions"] = _clean_perms(permissions)
    g["companies"] = sorted({str(c) for c in (companies or [])})
    g["members"] = sorted({str(m) for m in (members or [])})
    return g


def create_group(
    name: str,
    description: str = "",
    roles: list[str] | None = None,
    permissions: list[str] | None = None,
    companies: list[str] | None = None,
    members: list[str] | None = None,
) -> dict:
    """Create a group with a slugged id derived from its name (suffixed on clash)."""
    base = _slugify(name)
    existing = groups_index()
    group_id = base
    n = 2
    while group_id in existing:
        group_id = f"{base}-{n}"
        n += 1
    group = _normalize_group(
        group_id, name, description, roles, permissions, companies, members
    )

    def _add(store: dict) -> dict:
        if group_id in store:  # lost the race; caller can retry/rename
            raise ValueError(f"Group '{group_id}' already exists")
        store[group_id] = group
        return store

    mutate_json(_redis(), _GROUPS_KEY, _add, default={})
    _bump_groups_epoch()
    if group["members"]:
        _sync_user_groups_for_members(group_id, group["members"])
    return group


def update_group(
    group_id: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    roles: Optional[list[str]] = None,
    permissions: Optional[list[str]] = None,
    companies: Optional[list[str]] = None,
    members: Optional[list[str]] = None,
) -> dict:
    """Patch the supplied fields of a group (id is immutable)."""
    result: dict = {}

    def _patch(store: dict) -> dict:
        cur = store.get(group_id)
        if not cur:
            raise ValueError(f"Group '{group_id}' not found")
        merged = _normalize_group(
            group_id,
            name if name is not None else cur.get("name", group_id),
            description if description is not None else cur.get("description", ""),
            roles if roles is not None else cur.get("roles", []),
            permissions if permissions is not None else cur.get("permissions", []),
            companies if companies is not None else cur.get("companies", []),
            members if members is not None else cur.get("members", []),
        )
        store[group_id] = merged
        result["g"] = merged
        return store

    mutate_json(_redis(), _GROUPS_KEY, _patch, default={})
    # Roles/permissions/companies/members may all have changed: force every
    # worker to re-resolve rather than serve the pre-edit permission set.
    _bump_groups_epoch()
    if members is not None:
        # The members picker was edited — push the change into the canonical
        # user["groups"] field so enforcement matches the group view.
        _sync_user_groups_for_members(group_id, result["g"]["members"])
    return result["g"]


def delete_group(group_id: str) -> bool:
    """Delete a group. Returns False if it did not exist."""
    existed = {"v": False}

    def _del(store: dict) -> dict:
        if group_id in store:
            del store[group_id]
            existed["v"] = True
        return store

    mutate_json(_redis(), _GROUPS_KEY, _del, default={})
    _bump_groups_epoch()
    if existed["v"]:
        _sync_user_groups_for_members(group_id, [])  # strip from every user's groups
    return existed["v"]
