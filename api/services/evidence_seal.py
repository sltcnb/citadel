"""Court-ready signed evidence chain — cryptographically verifiable chain-of-custody.

Every sealed artifact is appended to a PER-CASE, append-only, hash-chained log.
Each seal's ``seal_hash`` commits to the previous seal's hash plus the canonical
JSON of the seal's own fields::

    seal_hash = sha256((prev_hash + canonical_json(record_without_seal_hash))).hexdigest()

Because every link commits to its predecessor, editing or deleting any seal in
the middle of the chain invalidates every subsequent ``seal_hash`` — that is the
tamper-evidence. ``verify_seals`` recomputes the chain to prove it is intact.

The chain alone is tamper-EVIDENT (any mutation is detectable). When an
``EVIDENCE_SIGNING_KEY`` is configured the court-ready manifest is additionally
HMAC-signed, making the manifest tamper-RESISTANT for anyone without the key.

Mirrors the chaining approach in ``services/audit.py``. Dependency-free
(``hashlib`` / ``hmac`` only).

Redis layout (per case)::

    fo:evidence:seal:{case_id}        list of seal records, JSON, OLDEST..NEWEST
    fo:evidence:seal:head:{case_id}   hash of the most recent seal (chain head)
    fo:evidence:seal:lock:{case_id}   short spin-lock around the head read-append
    fo:evidence:seal:anchor:{case_id} out-of-band {head_hash, length} anchor

``list_seals`` returns NEWEST-first (most recently sealed at index 0); the stored
chain and ``custody_manifest`` keep OLDEST-first (chain order).

Integrity model
---------------
* **Windowed verification** (``_verify_chain``) recomputes continuity over a slice
  of the chain and starts from whatever ``prev_hash`` the first held record
  declares. It detects any tamper *inside the window* but cannot, by itself, tell
  that the window's oldest seals were truncated.
* **Full verification** (``verify_seals`` / ``custody_manifest``) additionally
  asserts the chain is anchored to :data:`GENESIS_HASH` (the first record's
  ``prev_hash`` must equal genesis — otherwise the oldest seals were dropped) and
  cross-checks the live chain head+length against an **out-of-band anchor** stored
  under a separate key namespace. An attacker who rewrites the chain list but not
  the anchor (or vice-versa) is therefore detected.

Append atomicity
----------------
Appends use an optimistic compare-and-set (CAS) driven by two Lua scripts: one
atomically reads ``{head, length}``, the other appends the precomputed record +
head + anchor *only if* the head/length are still what we read. On a CAS miss the
append is recomputed and retried. Correctness no longer depends on the coarse
per-case lock (kept only as a contention reducer).

DB-backed authoritative anchor
------------------------------
The head+length anchor is ALSO persisted in the relational DB
(``models.evidence_seal_anchor.EvidenceSealAnchor``, one row per case) — an
**independent trust domain** from Redis. On each successful append the DB anchor
is upserted in the same logical operation (best-effort transactional: the Redis
append has already committed, so a DB-write failure is surfaced as a loud
integrity warning rather than failing the seal). Full verification treats the DB
anchor as **authoritative when present** and reports a distinct
``anchor_mismatch`` failure when the live chain head/length disagree with it. The
Redis anchor is retained as defense in depth. When the DB anchor table is
empty/absent (first run / migrations not applied) verification degrades to the
genesis + Redis checks with a noted lower assurance (``anchor_source == "none"``).

Residual assumption
-------------------
With the DB anchor present, an attacker must now compromise BOTH Redis (the chain
list) AND the relational DB (the authoritative anchor), consistently, to forge a
chain undetectably — the two live in independent stores. When only the Redis
anchor is available the weaker single-store assumption from the prior PR applies.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import UTC, datetime

from config import get_redis

logger = logging.getLogger(__name__)

# The DB-backed anchor lives in an independent trust domain from Redis and is
# treated as AUTHORITATIVE when present. Imports are done lazily inside the
# helpers below so that merely importing this module (e.g. for the pure hashing
# helpers, or before migrations have run) never requires SQLAlchemy or a live DB.

# ── Redis keys (per case) ─────────────────────────────────────────────────────
_LIST_PREFIX = "fo:evidence:seal:"          # + {case_id}        → chain list
_HEAD_PREFIX = "fo:evidence:seal:head:"     # + {case_id}        → chain head hash
_LOCK_PREFIX = "fo:evidence:seal:lock:"     # + {case_id}        → write lock
_ANCHOR_PREFIX = "fo:evidence:seal:anchor:"  # + {case_id}       → out-of-band anchor

# Genesis prev_hash for the first seal in an empty per-case chain.
GENESIS_HASH = "0" * 64

# Env name for the optional HMAC signing key.
_SIGNING_KEY_ENV = "EVIDENCE_SIGNING_KEY"

# How many times an optimistic CAS append is retried before giving up.
_APPEND_MAX_RETRIES = 25

# Lua: take the lock only if free, with a TTL. Returns 1 on acquire.
_LOCK_ACQUIRE = (
    "if redis.call('setnx', KEYS[1], ARGV[1]) == 1 then "
    "redis.call('pexpire', KEYS[1], ARGV[2]); return 1 else return 0 end"
)

# Lua: atomically read the current chain head and length.
# KEYS[1]=head key, KEYS[2]=list key. Returns {head_str_or_empty, length}.
# An empty-string head means the chain is empty (genesis start).
_READ_HEAD_LEN = (
    "local h = redis.call('get', KEYS[1]) "
    "if not h then h = '' end "
    "return {h, redis.call('llen', KEYS[2])}"
)

# Lua: compare-and-set append. Appends the precomputed record and updates the
# head + out-of-band anchor ATOMICALLY, but ONLY IF the observed head and length
# are still current (no concurrent writer moved the chain forward). Returns 1 on
# success, 0 on CAS miss (caller must recompute against the new head and retry).
# KEYS[1]=list, KEYS[2]=head, KEYS[3]=anchor
# ARGV[1]=observed_head ('' if empty), ARGV[2]=observed_len,
# ARGV[3]=record_json, ARGV[4]=new_head_hash, ARGV[5]=anchor_json
_CAS_APPEND = (
    "local cur = redis.call('get', KEYS[2]) "
    "if not cur then cur = '' end "
    "if cur ~= ARGV[1] then return 0 end "
    "if redis.call('llen', KEYS[1]) ~= tonumber(ARGV[2]) then return 0 end "
    "redis.call('rpush', KEYS[1], ARGV[3]) "
    "redis.call('set', KEYS[2], ARGV[4]) "
    "redis.call('set', KEYS[3], ARGV[5]) "
    "return 1"
)


def _list_key(case_id: str) -> str:
    return f"{_LIST_PREFIX}{case_id}"


def _head_key(case_id: str) -> str:
    return f"{_HEAD_PREFIX}{case_id}"


def _lock_key(case_id: str) -> str:
    return f"{_LOCK_PREFIX}{case_id}"


def _anchor_key(case_id: str) -> str:
    return f"{_ANCHOR_PREFIX}{case_id}"


# ── Pure helpers (unit-testable without Redis) ────────────────────────────────


def _canonical_json(record: dict) -> str:
    """Deterministic JSON for hashing — sorted keys, no incidental whitespace."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _seal_hash(prev_hash: str, record_without_seal_hash: dict) -> str:
    """The chain link: sha256(prev_hash + canonical_json(record_without_seal_hash))."""
    payload = prev_hash + _canonical_json(record_without_seal_hash)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _verify_chain(records: list[dict]) -> dict:
    """Recompute the chain over ``records`` (OLDEST-first / chain order).

    Returns ``{ok, broken_at, sealed_count}``. ``broken_at`` is the ``seq`` of the
    first seal whose stored ``seal_hash`` does not match the recomputation, or
    whose ``prev_hash`` does not chain to the running head — or ``None`` when intact.

    Verification starts from whatever ``prev_hash`` the first record declares (we
    may hold a window rather than the full history), then enforces continuity
    forward — so a tamper anywhere inside the window is detected via either a hash
    mismatch or a broken ``prev_hash`` link.
    """
    expected_prev: str | None = None
    for rec in records:
        seq = rec.get("seq")
        stored_hash = rec.get("seal_hash")
        stored_prev = rec.get("prev_hash")

        # Continuity: every seal after the first must chain to its predecessor.
        if expected_prev is not None and stored_prev != expected_prev:
            return {"ok": False, "broken_at": seq, "sealed_count": len(records)}

        without = {k: v for k, v in rec.items() if k != "seal_hash"}
        recomputed = _seal_hash(stored_prev or GENESIS_HASH, without)
        if recomputed != stored_hash:
            return {"ok": False, "broken_at": seq, "sealed_count": len(records)}

        expected_prev = stored_hash

    return {"ok": True, "broken_at": None, "sealed_count": len(records)}


def _verify_chain_full(records: list[dict]) -> dict:
    """FULL verification: the chain must be anchored to :data:`GENESIS_HASH`.

    Unlike :func:`_verify_chain` (which trusts the first held ``prev_hash`` and so
    accepts a truncated window), this asserts the very first record's ``prev_hash``
    equals genesis. If it does not, the oldest seals were dropped and we report a
    *distinct* ``reason == "not_anchored"`` failure (chain truncated / not anchored
    to genesis) rather than a generic hash break.

    Returns ``{ok, broken_at, sealed_count, reason}`` where ``reason`` is one of
    ``None`` (intact), ``"not_anchored"`` (truncated), or ``"broken"`` (a hash /
    continuity mismatch inside the chain, whose ``seq`` is ``broken_at``).
    """
    n = len(records)
    if n == 0:
        # An empty chain is trivially anchored (nothing has been sealed yet).
        return {"ok": True, "broken_at": None, "sealed_count": 0, "reason": None}

    first_prev = records[0].get("prev_hash")
    if first_prev != GENESIS_HASH:
        # First link does not chain to genesis → oldest seals were truncated.
        return {
            "ok": False,
            "broken_at": records[0].get("seq"),
            "sealed_count": n,
            "reason": "not_anchored",
        }

    windowed = _verify_chain(records)
    windowed["reason"] = None if windowed["ok"] else "broken"
    return windowed


def _manifest_hash(seals: list[dict]) -> str:
    """A single hash committing to all seals in chain order.

    Deterministic: hashes the canonical JSON of the seal list. Any change to any
    seal field — including a tampered ``seal_hash`` — changes the manifest hash.
    """
    payload = _canonical_json({"seals": seals})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _signing_key() -> bytes | None:
    """The configured HMAC signing key as bytes, or None when unset/empty."""
    key = os.environ.get(_SIGNING_KEY_ENV, "")
    return key.encode("utf-8") if key else None


def _sign(manifest_hash: str) -> dict:
    """Return a signing block for ``manifest_hash``.

    When a key is configured: ``{signed: True, algorithm, signature}`` where the
    signature is HMAC-SHA256 over the manifest hash. Otherwise ``{signed: False}``
    — the hash chain alone still provides tamper-evidence.
    """
    key = _signing_key()
    if not key:
        return {"signed": False, "algorithm": None, "signature": None}
    signature = hmac.new(key, manifest_hash.encode("utf-8"), hashlib.sha256).hexdigest()
    return {"signed": True, "algorithm": "HMAC-SHA256", "signature": signature}


# ── Redis-backed chain operations ─────────────────────────────────────────────


def _acquire_lock(r, case_id: str, token: str, ttl_ms: int = 2000, tries: int = 50) -> bool:
    """Best-effort short spin-lock guarding the per-case head read-append."""
    lk = _lock_key(case_id)
    for _ in range(tries):
        try:
            if r.eval(_LOCK_ACQUIRE, 1, lk, token, ttl_ms) == 1:
                return True
        except Exception:
            return False
        time.sleep(0.01)
    return False


def _release_lock(r, case_id: str, token: str) -> None:
    # Only release if we still own it (token match).
    try:
        if r.get(_lock_key(case_id)) == token:
            r.delete(_lock_key(case_id))
    except Exception:
        pass


def _read_chain(r, case_id: str) -> list[dict]:
    """Read the full per-case chain, OLDEST-first (chain order)."""
    try:
        raw = r.lrange(_list_key(case_id), 0, -1)
    except Exception:
        return []
    out: list[dict] = []
    for item in raw:
        try:
            out.append(json.loads(item))
        except (ValueError, TypeError):
            continue
    return out


def _read_anchor(r, case_id: str) -> dict | None:
    """Read the out-of-band {head_hash, length} anchor, or None when absent."""
    try:
        raw = r.get(_anchor_key(case_id))
    except Exception:
        return None
    if not raw:
        return None
    try:
        anchor = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if isinstance(anchor, dict) and "head_hash" in anchor and "length" in anchor:
        return anchor
    return None


# ── DB-backed authoritative anchor (independent trust domain) ─────────────────


def _write_db_anchor(case_id: str, head_hash: str, length: int) -> bool:
    """Upsert the authoritative ``{head_hash, length}`` anchor row for a case.

    Best-effort transactional: returns ``True`` on a committed write, ``False`` if
    the DB anchor could not be persisted (table absent / DB unreachable / etc.).
    Callers MUST log loudly on ``False`` — the chain append has already happened,
    so a failure here is an *integrity warning*, not a hard error.
    """
    try:
        import db
        from models.evidence_seal_anchor import EvidenceSealAnchor
    except Exception:  # pragma: no cover - SQLAlchemy/models unavailable
        return False
    try:
        with db.session_scope() as session:
            row = session.get(EvidenceSealAnchor, case_id)
            if row is None:
                session.add(
                    EvidenceSealAnchor(
                        case_id=case_id, head_hash=head_hash, length=length
                    )
                )
            else:
                row.head_hash = head_hash
                row.length = length
        return True
    except Exception:
        return False


def _read_db_anchor(case_id: str) -> dict | None:
    """Read the authoritative DB anchor as ``{head_hash, length}``, or None.

    Returns ``None`` when the table is absent/empty (first run / migrations not
    applied) or the DB is unreachable — callers then degrade to the genesis +
    Redis checks with a noted lower assurance.
    """
    try:
        import db
        from models.evidence_seal_anchor import EvidenceSealAnchor
    except Exception:  # pragma: no cover - SQLAlchemy/models unavailable
        return None
    try:
        with db.session_scope() as session:
            row = session.get(EvidenceSealAnchor, case_id)
            if row is None:
                return None
            return {"head_hash": row.head_hash, "length": row.length}
    except Exception:
        return None


def _verify_full(r, case_id: str) -> dict:
    """FULL verification of the live per-case chain.

    Combines :func:`_verify_chain_full` (genesis-anchored recompute) with a
    cross-check of the live chain head/length against an out-of-band anchor. The
    **DB anchor is authoritative when present** (independent trust domain from
    Redis); the Redis anchor is kept as defense in depth. When neither anchor is
    available we degrade to the genesis-only check and mark the lower assurance
    via ``anchor_source == "none"``.

    Returns ``{ok, broken_at, sealed_count, reason, anchor_ok, anchor_source}``.

    ``reason`` values: ``None`` (intact), ``"not_anchored"`` (truncated / not
    anchored to genesis), ``"broken"`` (internal hash/continuity break), or
    ``"anchor_mismatch"`` (chain head/length disagrees with the authoritative
    anchor — e.g. the chain list was rewritten but the anchor was not).
    ``anchor_source`` is one of ``"db"``, ``"redis"``, ``"none"``.
    """
    chain = _read_chain(r, case_id)
    result = _verify_chain_full(chain)
    result["anchor_ok"] = True

    live_head = chain[-1].get("seal_hash") if chain else GENESIS_HASH
    live_len = len(chain)

    # DB anchor is authoritative (independent trust domain); fall back to the
    # Redis anchor as defense in depth; if neither exists, note the degraded
    # (genesis-only) assurance via anchor_source == "none".
    db_anchor = _read_db_anchor(case_id)
    redis_anchor = _read_anchor(r, case_id)
    if db_anchor is not None:
        result["anchor_source"] = "db"
        anchor = db_anchor
    elif redis_anchor is not None:
        result["anchor_source"] = "redis"
        anchor = redis_anchor
    else:
        result["anchor_source"] = "none"
        anchor = None

    if anchor is not None:
        if anchor.get("head_hash") != live_head or anchor.get("length") != live_len:
            result["anchor_ok"] = False
            if result["ok"]:
                # Chain recomputes cleanly on its own, but disagrees with the
                # tamper-independent anchor → the list was rewritten under us.
                result["ok"] = False
                result["reason"] = "anchor_mismatch"
                result["broken_at"] = None

    # Defense in depth: even when the authoritative DB anchor agrees, a divergent
    # Redis mirror is worth surfacing (partial tamper / stale mirror).
    if (
        result["anchor_source"] == "db"
        and redis_anchor is not None
        and (
            redis_anchor.get("head_hash") != live_head
            or redis_anchor.get("length") != live_len
        )
    ):
        logger.warning(
            "Evidence seal Redis anchor disagrees with the authoritative DB anchor "
            "for case %r (redis=%s live_head=%s live_len=%d) — possible partial "
            "tamper or stale mirror.",
            case_id,
            redis_anchor,
            live_head,
            live_len,
        )
    return result


def seal_artifact(
    case_id: str,
    artifact_id: str,
    sha256: str,
    meta: dict | None = None,
    sealed_by: str = "",
) -> dict:
    """Append one immutable evidence seal to the per-case hash chain.

    Returns the full seal record (including its ``seal_hash``). ``seq`` is the
    1-based position in the chain.

    The append is an optimistic compare-and-set: we atomically read the current
    head+length, compute the record against them, then atomically append + advance
    the head + update the out-of-band anchor **only if** the head/length are still
    current. A concurrent writer that moved the chain forward causes a CAS miss and
    we recompute against the new head and retry. Correctness therefore does not
    depend on the coarse lock below (which only reduces contention).
    """
    r = get_redis()
    token = uuid.uuid4().hex
    # Coarse guard: reduces contention (fewer CAS misses) but is NOT required for
    # correctness — the CAS below is the real safety net. Proceed even if unheld.
    have_lock = _acquire_lock(r, case_id, token)
    try:
        list_key = _list_key(case_id)
        head_key = _head_key(case_id)
        anchor_key = _anchor_key(case_id)

        for _ in range(_APPEND_MAX_RETRIES):
            # 1) Atomically observe the current head + length.
            observed_head, observed_len = _read_head_len(r, head_key, list_key)
            prev_hash = observed_head or GENESIS_HASH
            seq = observed_len + 1

            # 2) Compute the record + seal_hash against the observed head.
            record_without_seal_hash = {
                "seq": seq,
                "case_id": case_id or "",
                "artifact_id": artifact_id or "",
                "sha256": (sha256 or "").lower(),
                "sealed_at": datetime.now(UTC).isoformat(),
                "sealed_by": sealed_by or "anonymous",
                "meta": meta or {},
                "prev_hash": prev_hash,
            }
            seal_hash = _seal_hash(prev_hash, record_without_seal_hash)
            record = {**record_without_seal_hash, "seal_hash": seal_hash}
            anchor_json = _canonical_json({"head_hash": seal_hash, "length": seq})

            # 3) Append IFF the head/length are unchanged (CAS). On a miss, another
            #    writer won the race — recompute against the new head and retry.
            applied = r.eval(
                _CAS_APPEND,
                3,
                list_key,
                head_key,
                anchor_key,
                observed_head,
                observed_len,
                _canonical_json(record),
                seal_hash,
                anchor_json,
            )
            if int(applied) == 1:
                # Mirror the new head/length to the AUTHORITATIVE DB anchor in the
                # same logical operation. Best-effort transactional: the chain
                # append already committed, so a DB failure here cannot be rolled
                # back — surface it loudly as an integrity warning rather than
                # failing the seal (which is durably recorded in Redis).
                if not _write_db_anchor(case_id, seal_hash, seq):
                    logger.warning(
                        "INTEGRITY WARNING: evidence seal appended for case %r "
                        "(seq=%d head=%s) but the authoritative DB anchor could "
                        "not be updated. The Redis chain and DB anchor are now out "
                        "of sync; full verification will report anchor_mismatch "
                        "until reconciled.",
                        case_id,
                        seq,
                        seal_hash,
                    )
                return record
        raise RuntimeError(
            f"Could not atomically append evidence seal for case {case_id!r} "
            f"after {_APPEND_MAX_RETRIES} CAS attempts (retry)."
        )
    finally:
        if have_lock:
            _release_lock(r, case_id, token)


def _read_head_len(r, head_key: str, list_key: str) -> tuple[str, int]:
    """Atomically read the current chain head hash and length via Lua."""
    res = r.eval(_READ_HEAD_LEN, 2, head_key, list_key)
    head = res[0]
    if isinstance(head, bytes):
        head = head.decode("utf-8")
    return (head or "", int(res[1]))


def list_seals(case_id: str) -> list[dict]:
    """Return the per-case seal chain, NEWEST-first (index 0 = most recent)."""
    r = get_redis()
    chain = _read_chain(r, case_id)  # oldest-first
    chain.reverse()
    return chain


def verify_seals(case_id: str) -> dict:
    """FULL integrity verification of the per-case chain.

    Recomputes the chain, asserts it is anchored to genesis (detecting truncation
    of the oldest seals), and cross-checks the live head/length against the
    out-of-band anchor (detecting a rewritten chain list).

    Returns ``{ok, broken_at, sealed_count, reason, anchor_ok, verified_at}``.
    """
    r = get_redis()
    result = _verify_full(r, case_id)
    result["verified_at"] = datetime.now(UTC).isoformat()
    return result


def custody_manifest(case_id: str) -> dict:
    """Build the court-ready, (optionally) signed custody manifest for a case.

    Includes every seal (chain order), the chain head, a ``manifest_hash`` over
    all seals, a verification result, an HMAC signature block, and a plain-English
    verification instruction.
    """
    r = get_redis()
    chain = _read_chain(r, case_id)  # oldest-first / chain order
    verification = _verify_full(r, case_id)
    head = chain[-1]["seal_hash"] if chain else GENESIS_HASH
    manifest_hash = _manifest_hash(chain)
    signature = _sign(manifest_hash)

    return {
        "document_type": "evidence_custody_manifest",
        "version": "1",
        "case_id": case_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "sealed_count": len(chain),
        "chain_head": head,
        "genesis_hash": GENESIS_HASH,
        "seals": chain,
        "manifest_hash": manifest_hash,
        "chain_intact": verification["ok"],
        "broken_at": verification["broken_at"],
        "verification_reason": verification.get("reason"),
        "anchor_ok": verification.get("anchor_ok", True),
        "anchor_source": verification.get("anchor_source", "none"),
        **signature,
        "verification_instruction": (
            "For each artifact, recompute its SHA-256 and compare to the seal's "
            "`sha256`. Then re-derive each seal's `seal_hash` as "
            "sha256(prev_hash + canonical_json(seal_without_seal_hash)) — where "
            "canonical_json uses sorted keys and ','/':' separators — confirming "
            "each seal's `prev_hash` equals the prior seal's `seal_hash`. Confirm "
            "the FIRST seal's `prev_hash` equals `genesis_hash` (all-zero) — if not, "
            "the oldest seals were truncated. Finally "
            "recompute `manifest_hash` = sha256(canonical_json({'seals': seals})). "
            "If a signature is present, recompute HMAC-SHA256(EVIDENCE_SIGNING_KEY, "
            "manifest_hash) and compare. Any mismatch indicates tampering."
        ),
    }
