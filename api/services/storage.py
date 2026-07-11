"""MinIO storage service with retry logic and a precise error hierarchy.

Callers should catch the typed exceptions defined here (``ObjectNotFound``,
``StorageUnavailable``, ``IntegrityError``) rather than bare ``Exception`` so
that data/evidence paths can surface an accurate HTTP status and log with
context. All object keys are prefixed ``cases/{case_id}/...``.
"""

from __future__ import annotations

import hashlib
import io
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import IO, Iterator

from config import settings

logger = logging.getLogger(__name__)

# ── Typed error hierarchy ──────────────────────────────────────────────────────


class StorageError(Exception):
    """Base class for all storage-layer failures."""


class ObjectNotFound(StorageError):
    """The requested object key does not exist in the bucket."""

    def __init__(self, object_key: str):
        self.object_key = object_key
        super().__init__(f"Object not found: {object_key}")


class StorageUnavailable(StorageError):
    """The storage backend is unreachable/transient — retries were exhausted."""


class IntegrityError(StorageError):
    """A downloaded object failed size or checksum verification."""


# Error substrings that indicate a transient connection problem worth retrying.
_CONN_ERRORS = (
    "connection refused",
    "max retries exceeded",
    "timeout",
    "reset by peer",
    "broken pipe",
    "connection reset",
    "read timeout",
    "write timeout",
    "remote end closed",
    "incomplete read",
    "econnreset",
    "epipe",
)

# S3Error codes that map to "object does not exist".
_NOT_FOUND_CODES = ("NoSuchKey", "NoSuchObject", "NoSuchBucket")


def _is_transient(exc: Exception) -> bool:
    return any(k in str(exc).lower() for k in _CONN_ERRORS)


def _is_not_found(exc: Exception) -> bool:
    """True if *exc* is a MinIO S3Error signalling a missing key."""
    code = getattr(exc, "code", None)
    return code in _NOT_FOUND_CODES


def _retry(fn, max_tries: int = 3, base_delay: float = 1.0):
    """
    Call *fn()* up to *max_tries* times with exponential back-off.

    Only retries when the exception looks like a transient network failure.
    All other errors are re-raised immediately on the first occurrence. When
    transient retries are exhausted the last error is wrapped in
    ``StorageUnavailable`` so callers get a precise, typed failure.
    """
    last_exc: Exception | None = None
    for attempt in range(max_tries):
        try:
            return fn()
        except Exception as exc:
            if _is_transient(exc):
                last_exc = exc
                if attempt < max_tries - 1:
                    wait = base_delay * (2**attempt)
                    logger.warning(
                        "MinIO transient error (attempt %d/%d): %s — retrying in %.0f s",
                        attempt + 1,
                        max_tries,
                        exc,
                        wait,
                    )
                    time.sleep(wait)
                    continue
                raise StorageUnavailable(str(exc)) from exc
            raise
    raise StorageUnavailable(str(last_exc))  # type: ignore[arg-type]


def get_minio():
    from minio import Minio

    return Minio(
        settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=False,
    )


def ensure_bucket() -> None:
    client = get_minio()

    def _check():
        if not client.bucket_exists(settings.MINIO_BUCKET):
            client.make_bucket(settings.MINIO_BUCKET)
            logger.info("Created MinIO bucket: %s", settings.MINIO_BUCKET)

    _retry(_check)


# ── Object metadata ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ObjectStat:
    """Lightweight snapshot of an object's server-side metadata."""

    object_key: str
    size: int
    etag: str
    last_modified: datetime | None
    content_type: str | None


def stat_object(object_key: str) -> ObjectStat:
    """Return metadata for *object_key* or raise :class:`ObjectNotFound`."""
    from minio.error import S3Error

    client = get_minio()

    def _do():
        return client.stat_object(settings.MINIO_BUCKET, object_key)

    try:
        st = _retry(_do)
    except S3Error as exc:
        if _is_not_found(exc):
            raise ObjectNotFound(object_key) from exc
        raise StorageError(str(exc)) from exc
    return ObjectStat(
        object_key=object_key,
        size=int(getattr(st, "size", 0) or 0),
        etag=(getattr(st, "etag", "") or "").strip('"'),
        last_modified=getattr(st, "last_modified", None),
        content_type=getattr(st, "content_type", None),
    )


# ── Uploads ─────────────────────────────────────────────────────────────────────


def upload_file(
    object_key: str, data: bytes, content_type: str = "application/octet-stream"
) -> str:
    """Upload raw bytes to MinIO with retry. Returns the object key."""
    client = get_minio()
    ensure_bucket()

    def _do():
        client.put_object(
            settings.MINIO_BUCKET,
            object_key,
            io.BytesIO(data),
            length=len(data),
            content_type=content_type,
        )

    _retry(_do)
    # High-frequency on ingest — DEBUG keeps the INFO stream signal-only.
    logger.debug("Uploaded %s (%d bytes)", object_key, len(data))
    return object_key


def upload_fileobj(object_key: str, fileobj: IO, size: int) -> str:
    """
    Upload a file-like object to MinIO with retry.

    Critical: the file position is reset to 0 before each attempt so that
    retries after a partial write do not send truncated data.
    """
    client = get_minio()
    ensure_bucket()

    def _do():
        try:
            fileobj.seek(0)
        except (AttributeError, OSError):
            pass
        client.put_object(
            settings.MINIO_BUCKET,
            object_key,
            fileobj,
            length=size,
        )

    _retry(_do)
    logger.debug("Uploaded %s (%d bytes)", object_key, size)
    return object_key


# ── Downloads ─────────────────────────────────────────────────────────────────


def download_fileobj(
    object_key: str,
    *,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> bytes:
    """Download an object from MinIO and return its contents as bytes.

    Raises :class:`ObjectNotFound` if the key is missing, and
    :class:`IntegrityError` if *expected_size* / *expected_sha256* is supplied
    and the downloaded bytes don't match. Connections are released on all paths.
    """
    from minio.error import S3Error

    client = get_minio()
    resp = None
    try:
        resp = client.get_object(settings.MINIO_BUCKET, object_key)
        data = resp.read()
    except S3Error as exc:
        if _is_not_found(exc):
            raise ObjectNotFound(object_key) from exc
        raise StorageError(str(exc)) from exc
    except Exception as exc:
        if _is_transient(exc):
            raise StorageUnavailable(str(exc)) from exc
        raise
    finally:
        if resp is not None:
            try:
                resp.close()
                resp.release_conn()
            except Exception:
                pass

    _verify_bytes(object_key, data, expected_size, expected_sha256)
    return data


def stream_object(
    object_key: str, chunk_size: int = 1024 * 1024
) -> Iterator[bytes]:
    """Yield an object's bytes in bounded chunks without buffering the whole
    body in RAM. Intended for large objects where the caller only streams.

    Raises :class:`ObjectNotFound` if the key is missing. The underlying
    connection is released when the generator is exhausted or closed.
    """
    from minio.error import S3Error

    client = get_minio()
    try:
        resp = client.get_object(settings.MINIO_BUCKET, object_key)
    except S3Error as exc:
        if _is_not_found(exc):
            raise ObjectNotFound(object_key) from exc
        raise StorageError(str(exc)) from exc
    try:
        yield from resp.stream(chunk_size)
    finally:
        try:
            resp.close()
            resp.release_conn()
        except Exception:
            pass


# ── Integrity helpers ──────────────────────────────────────────────────────────


def compute_sha256(data: bytes) -> str:
    """Return the hex SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def verify_sha256(data: bytes, expected_sha256: str) -> bool:
    """True if *data* hashes to *expected_sha256* (case-insensitive hex)."""
    return compute_sha256(data).lower() == expected_sha256.strip().lower()


def _verify_bytes(
    object_key: str,
    data: bytes,
    expected_size: int | None,
    expected_sha256: str | None,
) -> None:
    if expected_size is not None and len(data) != expected_size:
        raise IntegrityError(
            f"{object_key}: size mismatch (got {len(data)}, expected {expected_size})"
        )
    if expected_sha256 and not verify_sha256(data, expected_sha256):
        raise IntegrityError(
            f"{object_key}: sha256 mismatch (expected {expected_sha256})"
        )


# ── Deletion ─────────────────────────────────────────────────────────────────


def delete_object(object_key: str) -> None:
    """Remove an object from MinIO (no-op if it doesn't exist)."""
    client = get_minio()
    _retry(lambda: client.remove_object(settings.MINIO_BUCKET, object_key))
    logger.debug("Deleted MinIO object: %s", object_key)


def delete_case_objects(case_id: str) -> int:
    """
    Delete ALL MinIO objects under cases/{case_id}/ by prefix.

    Uses wildcard removal which is much faster than listing + batch deleting
    for cases with thousands of objects.

    Returns count of objects deleted (approximate for wildcard delete).
    """
    client = get_minio()
    prefix = f"cases/{case_id}/"

    # First, count objects to report
    try:
        objects = list(client.list_objects(settings.MINIO_BUCKET, prefix=prefix, recursive=True))
        count = len(objects)
    except Exception as exc:
        logger.warning("Failed to count objects for case %s: %s", case_id, exc)
        count = 0

    if count == 0:
        return 0

    # For large deletions, use remove_objects with generator (more efficient)
    try:
        from minio.deleteobjects import DeleteObject

        def object_generator():
            for obj in client.list_objects(settings.MINIO_BUCKET, prefix=prefix, recursive=True):
                yield DeleteObject(obj.object_name)

        errors = list(client.remove_objects(settings.MINIO_BUCKET, object_generator()))
        if errors:
            logger.warning("MinIO prefix delete %s: %d errors", prefix, len(errors))

        logger.info("Deleted %d MinIO objects under %s", count, prefix)
        return count

    except Exception as exc:
        logger.warning("MinIO delete failed for case %s: %s", case_id, exc)
        # Fallback: try with list (slower but more reliable)
        try:
            keys = [o.object_name for o in objects]
            errors = list(
                client.remove_objects(
                    settings.MINIO_BUCKET,
                    [DeleteObject(k) for k in keys],
                )
            )
            return len(keys) - len(errors)
        except Exception:
            return 0


def object_exists(object_key: str) -> bool:
    """Return True if the object exists in MinIO, False if it doesn't.

    Only a genuine "not found" returns False; connection/backend failures raise
    :class:`StorageUnavailable` / :class:`StorageError` so callers don't mistake
    an outage for a missing object.
    """
    from minio.error import S3Error

    client = get_minio()
    try:
        client.stat_object(settings.MINIO_BUCKET, object_key)
        return True
    except S3Error as exc:
        if _is_not_found(exc):
            return False
        raise StorageError(str(exc)) from exc
    except Exception as exc:
        if _is_transient(exc):
            raise StorageUnavailable(str(exc)) from exc
        raise


def list_objects(prefix: str, recursive: bool = True):
    """Yield ``minio`` object records under *prefix* (thin wrapper for reuse)."""
    client = get_minio()
    yield from client.list_objects(settings.MINIO_BUCKET, prefix=prefix, recursive=recursive)


def get_presigned_url(object_key: str, expires_seconds: int = 3600) -> str:
    """Generate a presigned download URL."""
    from datetime import timedelta

    client = get_minio()
    return client.presigned_get_object(
        settings.MINIO_BUCKET,
        object_key,
        expires=timedelta(seconds=expires_seconds),
    )
