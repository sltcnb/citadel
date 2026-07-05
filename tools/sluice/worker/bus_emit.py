"""
Bus emit + idempotency for Sluice (intake/processor).

Two concerns live here, both contract-driven (see contracts/bus_topics.md):

1. Bus emit — after a plugin parses an artifact into ForensicEvents, optionally
   publish those events to the Redis Streams topic `events.parsed` so Rosetta
   (the downstream consumer group) can normalize them to ECS v8. The pipeline
   is "at-least-once"; consumers dedup. Emit is gated behind BUS_EMIT_ENABLED so
   the existing ES-only flow is byte-for-byte unchanged when the flag is off.

2. Idempotent re-ingest — re-uploading the same artifact (same sha256) should be
   a no-op. We record each artifact sha256 in a Redis set keyed per case and skip
   anything already seen. Matches the bus guarantee that consumers dedup by sha256.

Nothing here imports celery or the heavy plugin stack, so it is unit-testable
with a tiny fake redis client (see tests/test_bus_emit.py).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

# ── Topic + key constants (mirror contracts/bus_topics.md) ────────────────────
TOPIC_EVENTS_PARSED = "events.parsed"

# Per-tenant isolation: bus_topics.md says topic keys carry the company id. The
# Redis Streams key embeds the company so a consumer group can shard per tenant.
_DEFAULT_COMPANY = "_global"

# Cap a single XADD batch so one giant artifact can't produce a multi-MB stream
# entry that the broker chokes on. Larger event sets are split across entries.
EMIT_BATCH_SIZE = int(os.getenv("BUS_EMIT_BATCH_SIZE", "500"))

# How long the dedup set for a case lives — matches the 7-day job TTL.
DEDUP_TTL_SECONDS = int(os.getenv("INGEST_DEDUP_TTL", str(7 * 86400)))


def bus_emit_enabled() -> bool:
    """True when the operator has opted into bus emit.

    Off by default: the existing ES-indexing flow is unchanged unless an operator
    sets BUS_EMIT_ENABLED to a truthy value (1/true/yes/on).
    """
    return os.getenv("BUS_EMIT_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}


def events_parsed_stream(company: str | None) -> str:
    """Redis Streams key for events.parsed, namespaced by tenant.

    e.g. company "acme" -> "bus:events.parsed:acme".
    """
    co = (company or _DEFAULT_COMPANY).strip() or _DEFAULT_COMPANY
    return f"bus:{TOPIC_EVENTS_PARSED}:{co}"


def _dedup_set_key(case_id: str) -> str:
    """Redis set holding every artifact sha256 already ingested for a case."""
    return f"fo:ingest:seen_sha256:{case_id}"


# ── Idempotency ───────────────────────────────────────────────────────────────


def compute_sha256(path) -> str:
    """Stream a file from disk and return its hex sha256 (chunked, low memory)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def mark_and_check_seen(r, case_id: str, sha256: str) -> bool:
    """Atomically record an artifact sha256 for a case.

    Returns True if this sha256 was ALREADY seen (caller should skip / treat the
    re-ingest as a no-op), False if it is new (caller should proceed).

    Uses SADD's return value (1 = newly added, 0 = already present) so the
    check-and-set is a single atomic round-trip — no check-then-set race when two
    workers pick up duplicate uploads concurrently.
    """
    if not sha256:
        return False
    key = _dedup_set_key(case_id)
    added = r.sadd(key, sha256)
    # Refresh TTL on every touch so an actively-ingested case never expires mid-run.
    try:
        r.expire(key, DEDUP_TTL_SECONDS)
    except Exception:  # pragma: no cover - expire failures are non-fatal
        logger.debug("Could not set TTL on dedup key %s", key)
    return added == 0


def forget_seen(r, case_id: str, sha256: str) -> None:
    """Remove a sha256 from the dedup set.

    Used when an ingest that claimed the sha256 fails before producing events, so
    a genuine retry of the same artifact isn't permanently skipped.
    """
    if sha256:
        try:
            r.srem(_dedup_set_key(case_id), sha256)
        except Exception:  # pragma: no cover
            logger.debug("Could not srem dedup key for case %s", case_id)


# ── forensic_event/v1 serialization ────────────────────────────────────────────

# Required by contracts/forensic_event.schema.json.
_REQUIRED_FIELDS = ("timestamp", "message")
# The contract recommends carrying these; we pass them through when present.
_PASSTHROUGH_FIELDS = (
    "timestamp",
    "message",
    "artifact_type",
    "timestamp_desc",
    "raw",
    "os",
    "source_path",
    "parser",
)


def to_forensic_event_v1(event: dict[str, Any]) -> dict[str, Any]:
    """Project an internal event dict onto a forensic_event/v1 payload.

    The internal events the ingest task builds (_merge_base_fields) are a superset
    of the contract — they carry ES-only bookkeeping (fo_id, case_id, ...). The
    bus payload keeps the contract-recommended fields plus any extra fields the
    schema permits (additionalProperties: true), but always guarantees the two
    required ones are present and well-typed.
    """
    out: dict[str, Any] = {}
    for f in _PASSTHROUGH_FIELDS:
        if f in event and event[f] is not None:
            out[f] = event[f]

    # `source_path` in the contract maps to our internal `source_file`.
    if "source_path" not in out and event.get("source_file"):
        out["source_path"] = event["source_file"]

    # Guarantee required fields (the ingest task already coerces these, but be
    # defensive — a bad payload must not poison the stream for Rosetta).
    ts = out.get("timestamp")
    if not isinstance(ts, str) or not ts.strip():
        out["timestamp"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    elif not ts.endswith("Z"):
        # Contract requires ISO-8601 with Z (UTC) — normalize offset forms.
        try:
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is not None:
                dt = dt.astimezone(UTC)
                fmt = "%Y-%m-%dT%H:%M:%S.%fZ" if dt.microsecond else "%Y-%m-%dT%H:%M:%SZ"
                out["timestamp"] = dt.strftime(fmt)
        except ValueError:
            pass  # leave as-is; validation rejects it downstream
    msg = out.get("message")
    if not isinstance(msg, str) or not msg.strip():
        out["message"] = out.get("artifact_type", "generic")
    return out


def validate_forensic_event_v1(payload: dict[str, Any]) -> None:
    """Validate a forensic_event/v1 payload before it hits the bus.

    Delegates to the single source of truth — ``citadel_contracts`` — so the
    on-the-wire contract is enforced in one place (required fields, ISO-8601 Z
    timestamp, raw-for-structured). Falls back to inline checks if the contract
    package isn't importable yet. Raises ValueError on violation.
    """
    try:
        from citadel_contracts import validate_forensic_event

        ok, err = validate_forensic_event(payload)
        if not ok:
            raise ValueError(f"forensic_event/v1: {err}")
    except ImportError:
        for f in _REQUIRED_FIELDS:
            v = payload.get(f)
            if not isinstance(v, str) or not v.strip():
                raise ValueError(f"forensic_event/v1: '{f}' must be a non-empty string")
        if "raw" in payload and not isinstance(payload["raw"], (dict, str)):
            raise ValueError("forensic_event/v1: 'raw' must be an object or string")
    if "os" in payload:
        allowed = {"windows", "linux", "macos", "mobile", "cross", "cloud", "network"}
        if payload["os"] not in allowed:
            raise ValueError(f"forensic_event/v1: 'os' must be one of {sorted(allowed)}")


def serialize_batch(
    events: Iterable[dict[str, Any]],
    *,
    case_id: str,
    job_id: str,
    company: str | None = None,
    validate: bool = True,
) -> dict[str, str]:
    """Build the Redis Streams field/value map for one events.parsed entry.

    The payload is a `forensic_event/v1` batch (per bus_topics.md). Every field is
    a string because Redis Streams values are byte strings; the events themselves
    are carried as a JSON array under the "events" field.
    """
    fos = [to_forensic_event_v1(e) for e in events]
    if validate:
        for fo in fos:
            validate_forensic_event_v1(fo)
    return {
        "schema": "forensic_event/v1",
        "topic": TOPIC_EVENTS_PARSED,
        "case_id": case_id,
        "company": (company or _DEFAULT_COMPANY),
        "job_id": job_id,
        "count": str(len(fos)),
        "emitted_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "events": json.dumps(fos, ensure_ascii=False, default=str),
    }


def emit_events_parsed(
    r,
    events: list[dict[str, Any]],
    *,
    case_id: str,
    job_id: str,
    company: str | None = None,
) -> int:
    """Publish parsed events to the events.parsed stream. Returns entries written.

    No-op (returns 0) when the feature flag is off or there are no events, so the
    caller can invoke this unconditionally. Failures are swallowed (logged) — bus
    emit is a side channel and must never fail an ingest that already indexed to ES.
    """
    if not bus_emit_enabled() or not events:
        return 0
    stream = events_parsed_stream(company)
    written = 0
    try:
        for i in range(0, len(events), EMIT_BATCH_SIZE):
            chunk = events[i : i + EMIT_BATCH_SIZE]
            fields = serialize_batch(chunk, case_id=case_id, job_id=job_id, company=company)
            r.xadd(stream, fields)
            written += 1
        logger.info(
            "[%s] bus emit: %d events.parsed entries (%d events) -> %s",
            job_id,
            written,
            len(events),
            stream,
        )
        # Surface the inter-tool data flow in Sluice's tool stream.
        try:
            from citadel_contracts.logship import tool_logger
            tool_logger("sluice", r).info(
                "[Sluice → bus] %d events → %s (case %s) → consumed by Rosetta",
                len(events), TOPIC_EVENTS_PARSED, case_id,
            )
        except Exception:
            pass
    except Exception as exc:
        # Side channel: never break the indexing path. Rosetta can also be fed by
        # replaying ES; a missed emit is recoverable, a failed ingest is not.
        logger.warning("[%s] bus emit to %s failed: %s", job_id, stream, exc)
    return written
