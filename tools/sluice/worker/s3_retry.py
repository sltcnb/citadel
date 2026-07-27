"""Shared MinIO/S3 retry policy and byte-complete upload helper.

Lives at the worker root (next to ``robustness``/``redis_keys``) so every task
module classifies storage errors the same way — and so the policy is unit
testable without dragging in Celery.

Why the verification helper exists: MinIO answered a results.json PUT with
``IncompleteBody`` ("You did not provide the number of bytes specified by the
Content-Length HTTP header") — the request body was shorter than the announced
length. That error was not in the retry set, so a single hiccup bubbled up and
failed an entire module run whose hits were already indexed. A truncated PUT is
transient by nature: re-sending the same buffer fixes it.
"""

from __future__ import annotations

import io
import logging
import time

logger = logging.getLogger(__name__)

# Error substrings that make a storage operation worth retrying.
#
# The first group is connectivity. The second is server-side transients that a
# clean re-send resolves: IncompleteBody (truncated request body), SlowDown /
# InternalError / RequestTimeout / 503 (MinIO under load or mid-restart).
TRANSIENT_MARKERS: tuple[str, ...] = (
    # ── connectivity ──────────────────────────────────────────────────────────
    "connection refused",
    "max retries",
    "timeout",
    "connect",
    "reset by peer",
    "broken pipe",
    "connection reset",
    "econnrefused",
    "remote end closed",
    "incomplete read",
    # ── server-side transients ────────────────────────────────────────────────
    "incompletebody",
    "slowdown",
    "internalerror",
    "internal error",
    "service unavailable",
    "requesttimeout",
)


def is_transient(exc: Exception) -> bool:
    """True if *exc* looks like a storage failure a retry can clear."""
    return any(marker in str(exc).lower() for marker in TRANSIENT_MARKERS)


def minio_op(fn, max_tries: int = 4, base_delay: float = 3.0):
    """Execute ``fn()``, retrying transient storage errors with exponential backoff.

    Non-transient errors (AccessDenied, NoSuchBucket, …) are re-raised on the
    first occurrence — burning retries on them only delays the real report.
    """
    last_exc: Exception | None = None
    for attempt in range(max_tries):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - retry dispatcher; non-transient re-raised below
            if is_transient(exc):
                last_exc = exc
                if attempt < max_tries - 1:
                    wait = base_delay * (2**attempt)
                    logger.warning(
                        "MinIO attempt %d/%d failed (%s). Retrying in %.0fs…",
                        attempt + 1,
                        max_tries,
                        exc,
                        wait,
                    )
                    time.sleep(wait)
                    continue
            raise
    raise last_exc  # type: ignore[misc]


def put_bytes_verified(
    minio,
    bucket: str,
    key: str,
    payload: bytes,
    content_type: str = "application/octet-stream",
) -> None:
    """PUT *payload* under *key*, then prove the stored object is byte-complete.

    ``length`` comes from the encoded buffer itself, so Content-Length can never
    disagree with the body (the classic desync is measuring a ``str`` while
    sending UTF-8 bytes). The follow-up ``stat_object`` closes the remaining
    hole: a short write the server accepted would otherwise surface much later
    as unparseable JSON. A mismatch is raised as ``IncompleteBody`` so
    :func:`minio_op` retries it.
    """
    minio.put_object(
        bucket,
        key,
        io.BytesIO(payload),
        length=len(payload),
        content_type=content_type,
    )
    stored = minio.stat_object(bucket, key).size
    if stored != len(payload):
        raise OSError(
            f"IncompleteBody: {key} stored {stored} of {len(payload)} bytes — retrying upload"
        )
