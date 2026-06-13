"""Persistent, tamper-evident audit trail (chain-of-custody for an evidence platform).

Every mutating request is recorded as an append-only, hash-chained record. Each
record's ``hash`` is derived from the previous record's hash plus the canonical
JSON of the record's own fields::

    hash = sha256((prev_hash + canonical_json(record_without_hash)).encode()).hexdigest()

Because each link commits to the one before it, editing or deleting any record
in the middle of the chain invalidates every subsequent hash — that's the
tamper-evidence. ``verify_chain`` recomputes the chain to prove it is intact.

Durability is two-tier:
  * Redis  — a capped list for fast "recent events" reads + the chain head.
  * Elasticsearch (``fo-audit-log``) — durable, queryable long-term store.

ES indexing is BEST-EFFORT: if ES is down we keep the Redis copy and log a
warning. Audit indexing must never fail or slow the request it is recording.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime

from config import get_redis

logger = logging.getLogger(__name__)

# ── Redis keys ──────────────────────────────────────────────────────────────
# Fixed keys hold the chain state; the list holds recent records newest-last.
_SEQ_KEY = "fo:audit:seq"          # atomic INCR counter → monotonic seq
_HEAD_KEY = "fo:audit:head"        # hash of the most recent record (chain head)
_LIST_KEY = "fo:audit:log"         # capped list of record JSON (oldest..newest)
_LOCK_KEY = "fo:audit:lock"        # short lock guarding the read-append of head
_LIST_MAX = 50000                  # keep the Redis recent-window bounded

# The genesis prev_hash for the very first record in an empty chain.
GENESIS_HASH = "0" * 64

ES_INDEX = "fo-audit-log"

# Lua: take the lock only if free, set with a TTL. Returns 1 on acquire.
_LOCK_ACQUIRE = (
    "if redis.call('setnx', KEYS[1], ARGV[1]) == 1 then "
    "redis.call('pexpire', KEYS[1], ARGV[2]); return 1 else return 0 end"
)


def _canonical_json(record: dict) -> str:
    """Deterministic JSON for hashing — sorted keys, no incidental whitespace."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(prev_hash: str, record_without_hash: dict) -> str:
    """The chain link: sha256(prev_hash + canonical_json(record_without_hash))."""
    payload = prev_hash + _canonical_json(record_without_hash)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _acquire_lock(r, token: str, ttl_ms: int = 2000, tries: int = 50) -> bool:
    """Best-effort short spin-lock around the head read-append. The seq itself is
    allocated by an atomic INCR, so even if the lock is unavailable the chain
    cannot reuse a sequence number."""
    import time

    for _ in range(tries):
        try:
            if r.eval(_LOCK_ACQUIRE, 1, _LOCK_KEY, token, ttl_ms) == 1:
                return True
        except Exception:
            return False
        time.sleep(0.01)
    return False


def _release_lock(r, token: str) -> None:
    # Only release if we still own it (token match) — avoid clobbering a lock
    # whose TTL already expired and was re-taken by another writer.
    try:
        if r.get(_LOCK_KEY) == token:
            r.delete(_LOCK_KEY)
    except Exception:
        pass


def _index_es(record: dict) -> None:
    """Best-effort durable index into Elasticsearch. Never raises."""
    try:
        from services.elasticsearch import es_request

        es_request("PUT", f"/{ES_INDEX}/_doc/{record['seq']}", record)
    except Exception as exc:  # noqa: BLE001 — ES is optional for audit durability
        logger.warning("audit: ES indexing failed (kept in Redis) for seq=%s: %s",
                       record.get("seq"), exc)


def record_event(
    actor: str,
    role: str,
    method: str,
    path: str,
    case_id: str,
    status: int,
    ip: str,
) -> dict:
    """Append one tamper-evident record to the chain and persist it.

    Returns the full record (including its hash). Raising is avoided by the
    caller, but the chain operations themselves are kept tight: an atomic INCR
    for ``seq`` and a short lock around the head read-append so concurrent
    writers chain correctly.
    """
    import uuid

    r = get_redis()

    # Monotonic, never-reused sequence number (atomic even without the lock).
    seq = int(r.incr(_SEQ_KEY))

    token = uuid.uuid4().hex
    have_lock = _acquire_lock(r, token)
    try:
        prev_hash = r.get(_HEAD_KEY) or GENESIS_HASH

        record_without_hash = {
            "seq": seq,
            "ts": datetime.now(UTC).isoformat(),
            "actor": actor or "anonymous",
            "role": role or "",
            "method": method,
            "path": path,
            "case_id": case_id or "",
            "status": int(status),
            "ip": ip or "",
            "prev_hash": prev_hash,
        }
        record_hash = compute_hash(prev_hash, record_without_hash)
        record = {**record_without_hash, "hash": record_hash}

        # Advance the chain head and persist to the recent-window list.
        r.set(_HEAD_KEY, record_hash)
        r.rpush(_LIST_KEY, _canonical_json(record))
        r.ltrim(_LIST_KEY, -_LIST_MAX, -1)
    finally:
        if have_lock:
            _release_lock(r, token)

    # Durable, queryable copy — best-effort, off the critical path.
    _index_es(record)
    return record


def _read_recent(r, count: int) -> list[dict]:
    """Recent records from the Redis list, OLDEST-first (chain order)."""
    try:
        n = r.llen(_LIST_KEY)
    except Exception:
        return []
    if not n:
        return []
    start = max(0, n - count) if count else 0
    raw = r.lrange(_LIST_KEY, start, -1)
    out: list[dict] = []
    for item in raw:
        try:
            out.append(json.loads(item))
        except (ValueError, TypeError):
            continue
    return out


def list_events(
    limit: int = 100,
    offset: int = 0,
    actor: str | None = None,
    case_id: str | None = None,
) -> list[dict]:
    """Return recent audit records NEWEST-first, with optional filtering.

    Reads from the Redis recent-window. Filtering is applied before pagination
    so ``limit``/``offset`` page over the filtered set.
    """
    r = get_redis()
    # Pull a generous window so filters + offset have material to page over.
    window = max(limit + offset, 0) * 4 + 1000
    records = _read_recent(r, window)
    records.reverse()  # newest-first

    if actor:
        records = [rec for rec in records if rec.get("actor") == actor]
    if case_id:
        records = [rec for rec in records if rec.get("case_id") == case_id]

    return records[offset: offset + limit] if limit else records[offset:]


def verify_chain(limit: int = 1000) -> dict:
    """Walk the most recent ``limit`` records and recompute each hash from
    ``prev_hash`` + payload. Proves the chain has not been tampered with.

    Returns ``{ok, broken_at, checked}``. ``broken_at`` is the ``seq`` of the
    first record whose stored hash does not match the recomputation, or whose
    ``prev_hash`` does not match the running head — or ``None`` when intact.

    Note: verification starts from whatever ``prev_hash`` the first record in the
    window declares (we may not hold the full history in Redis), then enforces
    continuity from there forward — so a tamper anywhere inside the window is
    detected via either a hash mismatch or a broken prev_hash link.
    """
    r = get_redis()
    records = _read_recent(r, limit)  # oldest-first
    checked = 0
    expected_prev: str | None = None

    for rec in records:
        checked += 1
        seq = rec.get("seq")
        stored_hash = rec.get("hash")
        stored_prev = rec.get("prev_hash")

        # Continuity: every record after the first must chain to its predecessor.
        if expected_prev is not None and stored_prev != expected_prev:
            return {"ok": False, "broken_at": seq, "checked": checked}

        without_hash = {k: v for k, v in rec.items() if k != "hash"}
        recomputed = compute_hash(stored_prev or GENESIS_HASH, without_hash)
        if recomputed != stored_hash:
            return {"ok": False, "broken_at": seq, "checked": checked}

        expected_prev = stored_hash

    return {"ok": True, "broken_at": None, "checked": checked}
