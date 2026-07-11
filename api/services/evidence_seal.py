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

``list_seals`` returns NEWEST-first (most recently sealed at index 0); the stored
chain and ``custody_manifest`` keep OLDEST-first (chain order).
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

# ── Redis keys (per case) ─────────────────────────────────────────────────────
_LIST_PREFIX = "fo:evidence:seal:"          # + {case_id}        → chain list
_HEAD_PREFIX = "fo:evidence:seal:head:"     # + {case_id}        → chain head hash
_LOCK_PREFIX = "fo:evidence:seal:lock:"     # + {case_id}        → write lock

# Genesis prev_hash for the first seal in an empty per-case chain.
GENESIS_HASH = "0" * 64

# Env name for the optional HMAC signing key.
_SIGNING_KEY_ENV = "EVIDENCE_SIGNING_KEY"

# Lua: take the lock only if free, with a TTL. Returns 1 on acquire.
_LOCK_ACQUIRE = (
    "if redis.call('setnx', KEYS[1], ARGV[1]) == 1 then "
    "redis.call('pexpire', KEYS[1], ARGV[2]); return 1 else return 0 end"
)


def _list_key(case_id: str) -> str:
    return f"{_LIST_PREFIX}{case_id}"


def _head_key(case_id: str) -> str:
    return f"{_HEAD_PREFIX}{case_id}"


def _lock_key(case_id: str) -> str:
    return f"{_LOCK_PREFIX}{case_id}"


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


def seal_artifact(
    case_id: str,
    artifact_id: str,
    sha256: str,
    meta: dict | None = None,
    sealed_by: str = "",
) -> dict:
    """Append one immutable evidence seal to the per-case hash chain.

    Returns the full seal record (including its ``seal_hash``). ``seq`` is the
    1-based position in the chain (derived from the chain length under the lock).
    """
    r = get_redis()
    token = uuid.uuid4().hex
    have_lock = _acquire_lock(r, case_id, token)
    if not have_lock:
        # Appending without the lock lets two concurrent seals read the same
        # head/seq and fork the chain — permanently breaking the custody chain
        # this module exists to guarantee. Fail instead of corrupting it.
        raise RuntimeError(
            f"Could not acquire evidence-seal lock for case {case_id!r}; "
            "refusing to append (retry)."
        )
    try:
        prev_hash = r.get(_head_key(case_id)) or GENESIS_HASH
        try:
            seq = int(r.llen(_list_key(case_id))) + 1
        except Exception:
            seq = 1

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

        r.rpush(_list_key(case_id), _canonical_json(record))
        r.set(_head_key(case_id), seal_hash)
    finally:
        if have_lock:
            _release_lock(r, case_id, token)
    return record


def list_seals(case_id: str) -> list[dict]:
    """Return the per-case seal chain, NEWEST-first (index 0 = most recent)."""
    r = get_redis()
    chain = _read_chain(r, case_id)  # oldest-first
    chain.reverse()
    return chain


def verify_seals(case_id: str) -> dict:
    """Recompute the per-case chain and report integrity.

    Returns ``{ok, broken_at, sealed_count, verified_at}``.
    """
    r = get_redis()
    chain = _read_chain(r, case_id)  # oldest-first / chain order
    result = _verify_chain(chain)
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
    verification = _verify_chain(chain)
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
        **signature,
        "verification_instruction": (
            "For each artifact, recompute its SHA-256 and compare to the seal's "
            "`sha256`. Then re-derive each seal's `seal_hash` as "
            "sha256(prev_hash + canonical_json(seal_without_seal_hash)) — where "
            "canonical_json uses sorted keys and ','/':' separators — confirming "
            "each seal's `prev_hash` equals the prior seal's `seal_hash`. Finally "
            "recompute `manifest_hash` = sha256(canonical_json({'seals': seals})). "
            "If a signature is present, recompute HMAC-SHA256(EVIDENCE_SIGNING_KEY, "
            "manifest_hash) and compare. Any mismatch indicates tampering."
        ),
    }
