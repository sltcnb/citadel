"""File upload and ingest job dispatch.

Strategy:
  1. Stream each uploaded file to a local temp file in 4 MB async chunks.
     Using UploadFile.read() (which internally uses run_in_threadpool) ensures
     the event loop is never blocked, so other requests remain responsive even
     during 500 MB+ uploads.
  2. Return job IDs immediately after spooling, with status UPLOADING.
  3. Upload from the temp file to MinIO in a BackgroundTask — so the HTTP
     response is sent before the (potentially slow) MinIO transfer completes.
     This prevents proxy timeout errors (Traefik / Vite dev proxy) on large files.

Status lifecycle: UPLOADING → PENDING → RUNNING → COMPLETED | FAILED
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import logging
import os
import re
import tempfile
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from auth.dependencies import require_case_access, require_upload_access
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from services import jobs as job_svc
from services import storage
from services.cases import get_case
from services.safe_paths import UnsafePathError, safe_join

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ingest"])

# Temp directory for in-progress chunked uploads.
# Must be on a shared PVC so that chunks written by one API replica are visible
# to whichever replica receives the final chunk.
# In K8s: set CHUNK_DIR=/app/uploads/_chunks (uploads-pvc, 500Gi).
# In Docker: both compose files set CHUNK_DIR=/app/uploads/_chunks (writable
# uploads volume) — the /app/babel/_chunks default only suits the legacy layout
# where /app/babel was a writable plugins volume.
import os as _os

_CHUNK_DIR = Path(_os.environ.get("CHUNK_DIR", "/app/babel/_chunks"))

# Chunked-upload integrity limits.
# 50 MB client chunks × 10 000 = 500 GB ceiling — far past any legit file.
_MAX_CHUNKS = 10_000
# Abandoned chunk assemblies (client never sent the final chunk) are swept
# once they're older than this, opportunistically at chunk-finalize time.
_CHUNK_STALE_SECONDS = 24 * 3600
_CHUNK_META_SUFFIX = ".chunks.json"
# Advisory lock guarding the read-check-append-write on a chunk ledger. Held on
# a dedicated file rather than the ledger itself, because rewriting the ledger
# replaces its inode and would drop a lock taken on the old one.
_CHUNK_LOCK_SUFFIX = ".chunks.lock"


class _DuplicateChunk(Exception):
    """A chunk index was resent for the same upload_id."""


def _load_chunk_meta(meta_path: Path) -> dict:
    """Per-upload chunk ledger: which chunk indexes were received and how many
    bytes they carried. Missing/corrupt ledger → empty upload."""
    try:
        data = json.loads(meta_path.read_text())
        if isinstance(data, dict) and isinstance(data.get("indexes"), list):
            indexes = [int(i) for i in data["indexes"]]
            return {"indexes": indexes, "bytes": int(data.get("bytes", 0))}
    except Exception:  # noqa: BLE001 - corrupt ledger is treated as a fresh upload
        pass
    return {"indexes": [], "bytes": 0}


def _sweep_stale_chunks() -> None:
    """Delete chunk-assembly files (and their ledgers) older than
    _CHUNK_STALE_SECONDS. Best-effort; called when an upload finalizes."""
    try:
        cutoff = datetime.now(UTC).timestamp() - _CHUNK_STALE_SECONDS
        for p in _ensure_chunk_dir().iterdir():
            try:
                if p.is_file() and p.stat().st_mtime < cutoff:
                    p.unlink()
            except OSError:
                pass
    except OSError:
        pass


def _ensure_chunk_dir() -> Path:
    """Create the chunk directory on first use.

    Deferred from import time so the module (and the FastAPI app) can be
    imported in environments where the target path is not writable — e.g. a
    read-only filesystem in unit tests or CI. The directory is genuinely needed
    only when a chunked upload is actually received.
    """
    _CHUNK_DIR.mkdir(parents=True, exist_ok=True)
    return _CHUNK_DIR


# ── Known auxiliary / empty-by-design file types ──────────────────────────────
# These are always 0 bytes and have no forensic value; skip silently.
_AUXILIARY_SUFFIXES = frozenset(
    [
        ".sqlite-wal",
        ".sqlite-shm",
        ".db-wal",
        ".db-shm",
        "-wal",
        "-shm",
    ]
)
_AUXILIARY_NAMES = frozenset(["context_open.marker"])


def _require_writable_case(case_id: str) -> dict:
    """Fetch a case and refuse writes if it's archived.

    Archived cases are read-only — analysts must restore the case from its
    S3 archive (which lives at a different endpoint) before ingesting more.
    """
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if case.get("status") == "archived":
        raise HTTPException(
            status_code=409,
            detail="Case is archived — new ingestion is disabled. Restore from S3 archive first.",
        )
    return case


def _is_auxiliary(name: str) -> bool:
    n = name.lower()
    for s in _AUXILIARY_SUFFIXES:
        if n.endswith(s):
            return True
    return n in _AUXILIARY_NAMES


# ── SHA-256 integrity ─────────────────────────────────────────────────────────


def _compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Celery dispatch ────────────────────────────────────────────────────────────


def _dispatch_celery_task(job_id: str, case_id: str, minio_key: str, filename: str) -> None:
    """Dispatch a Celery ingest task via direct Redis push."""
    from services.celery_dispatch import dispatch_ingest

    dispatch_ingest(job_id, case_id, minio_key, filename)


# ── Background upload helper ──────────────────────────────────────────────────


def _bg_upload_and_dispatch(
    job_id: str,
    case_id: str,
    minio_key: str,
    filename: str,
    tmp_path: str,
    source_zip: str = "",
) -> None:
    """
    BackgroundTask: stream file from local staging to MinIO, then dispatch Celery task.

    Runs after the HTTP response has been sent, so the browser never waits for
    the potentially slow MinIO upload.  Status transitions:
      UPLOADING → (MinIO upload complete) → PENDING → (Celery processes) → COMPLETED / FAILED
    """
    try:
        size = os.path.getsize(tmp_path)
        sha256 = _compute_sha256(tmp_path)
        with open(tmp_path, "rb") as f:
            storage.upload_fileobj(minio_key, f, size)

        job_svc.update_job(job_id, minio_object_key=minio_key, status="PENDING", sha256=sha256)

        try:
            _dispatch_celery_task(job_id, case_id, minio_key, filename)
        except Exception as exc:
            logger.error("Celery dispatch failed for '%s': %s", filename, exc)
            job_svc.update_job(job_id, status="FAILED", error=f"Task dispatch failed: {exc}")

    except Exception as exc:
        logger.error("Background MinIO upload failed for '%s': %s", filename, exc)
        try:
            job_svc.update_job(job_id, status="FAILED", error=f"Upload failed: {exc}")
        except Exception:
            pass
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ── Single-file ingest (async) ─────────────────────────────────────────────────


def _ingest_one_async(
    case_id: str,
    filename: str,
    tmp_path: str,
    size: int,
    dispatched: list,
    errors: list,
    background_tasks: BackgroundTasks,
    source_zip: str = "",
    keep_raw: bool = False,
) -> None:
    """Create job record, register background upload, append to dispatched."""
    if size == 0:
        if _is_auxiliary(filename):
            logger.debug("Skipping empty auxiliary file: %s", filename)
        else:
            logger.warning("Skipping empty file: %s", filename)
            # Surface the drop — a 0-byte upload is usually a collection error
            # and must not vanish into a server log only.
            errors.append({"filename": filename, "error": "Empty file (0 bytes) — skipped"})
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return

    job_id = uuid.uuid4().hex
    minio_key = f"cases/{case_id}/{job_id}/{filename}"

    job_svc.create_job(job_id, case_id, filename, "", source_zip=source_zip, keep_raw=keep_raw)
    job_svc.update_job(job_id, status="UPLOADING", size_bytes=size)

    background_tasks.add_task(
        _bg_upload_and_dispatch, job_id, case_id, minio_key, filename, tmp_path, source_zip
    )

    entry: dict = {
        "job_id": job_id,
        "filename": filename,
        "status": "UPLOADING",
        "size_bytes": size,
    }
    if source_zip:
        entry["source_zip"] = source_zip
    dispatched.append(entry)


# ── ZIP extraction ─────────────────────────────────────────────────────────────

# Decompression-bomb caps — a small zip can expand to fill the disk / MinIO.
_MAX_UNCOMPRESSED_PER_FILE = int(os.getenv("MAX_ZIP_ENTRY_BYTES", str(10 * 1024**3)))   # 10 GiB
_MAX_UNCOMPRESSED_TOTAL = int(os.getenv("MAX_ZIP_TOTAL_BYTES", str(100 * 1024**3)))     # 100 GiB


def _bounded_copy(src, dst, limit: int) -> int:
    """Stream src→dst, aborting if more than `limit` uncompressed bytes are read
    (defends against lying ZIP headers / decompression bombs)."""
    written = 0
    while True:
        chunk = src.read(1024 * 1024)
        if not chunk:
            break
        written += len(chunk)
        if written > limit:
            raise ValueError(f"entry exceeds uncompressed size cap ({limit} bytes)")
        dst.write(chunk)
    return written


def _extract_and_dispatch_bg(
    case_id: str,
    zip_name: str,
    zip_tmp_path: str,
    entries: list,  # list of (zip_entry_path, entry_name, job_id, minio_key)
) -> None:
    """
    BackgroundTask: extract each ZIP entry, upload to MinIO, dispatch Celery.

    Runs after the HTTP response has been sent.  Each job transitions:
      UPLOADING → PENDING → (Celery) RUNNING → COMPLETED | FAILED
    """
    try:
        zf = zipfile.ZipFile(zip_tmp_path, "r")
    except Exception as exc:
        logger.error("Cannot open zip '%s' in background: %s", zip_name, exc)
        for _, _, job_id, _ in entries:
            try:
                job_svc.update_job(job_id, status="FAILED", error=f"ZIP open failed: {exc}")
            except Exception:
                pass
        try:
            os.unlink(zip_tmp_path)
        except OSError:
            pass
        return

    total_uncompressed = 0
    with zf:
        for zip_entry, entry_name, job_id, minio_key in entries:
            tmp_path = None
            base_name = entry_name.split("/")[-1]  # safe basename for temp file suffix
            try:
                # Reject obviously huge entries by declared size before extracting.
                declared = getattr(zip_entry, "file_size", 0) or 0
                if declared > _MAX_UNCOMPRESSED_PER_FILE:
                    raise ValueError(f"entry too large: {declared} bytes (cap {_MAX_UNCOMPRESSED_PER_FILE})")
                tmp_fd, tmp_path = tempfile.mkstemp(prefix="fo_zip_", suffix=f"_{base_name}")
                os.close(tmp_fd)
                with zf.open(zip_entry) as src, open(tmp_path, "wb") as dst:
                    written = _bounded_copy(src, dst, _MAX_UNCOMPRESSED_PER_FILE)
                total_uncompressed += written
                if total_uncompressed > _MAX_UNCOMPRESSED_TOTAL:
                    raise ValueError(f"archive exceeds total uncompressed cap ({_MAX_UNCOMPRESSED_TOTAL} bytes)")

                size = os.path.getsize(tmp_path)
                sha256 = _compute_sha256(tmp_path)
                job_svc.update_job(job_id, size_bytes=size, sha256=sha256)

                with open(tmp_path, "rb") as f:
                    storage.upload_fileobj(minio_key, f, size)

                job_svc.update_job(job_id, minio_object_key=minio_key, status="PENDING")

                try:
                    # Pass the full relative path (entry_name) as original_filename so
                    # process_artifact() gets directory context for plugin routing.
                    _dispatch_celery_task(job_id, case_id, minio_key, entry_name)
                except Exception as exc:
                    logger.error("Celery dispatch failed for '%s': %s", entry_name, exc)
                    job_svc.update_job(
                        job_id, status="FAILED", error=f"Task dispatch failed: {exc}"
                    )

            except Exception as exc:
                logger.error("Background extraction failed for '%s': %s", entry_name, exc)
                try:
                    job_svc.update_job(job_id, status="FAILED", error=f"Extraction failed: {exc}")
                except Exception:
                    pass
            finally:
                if tmp_path:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

    try:
        os.unlink(zip_tmp_path)
    except OSError:
        pass


def _handle_zip_async(
    case_id: str,
    zip_name: str,
    zip_tmp_path: str,
    dispatched: list,
    errors: list,
    background_tasks: BackgroundTasks,
    keep_raw: bool = False,
) -> None:
    """
    Phase 1 (sync, fast): read ZIP central directory, create job stubs, return immediately.
    Phase 2 (background): extract files, upload to MinIO, dispatch Celery tasks.

    Reading the central directory is O(1) — it never decompresses anything, so this
    completes in < 1s even for a 1.5 GB archive.  The HTTP response is sent before
    any extraction begins, preventing proxy 502 timeouts.
    """
    try:
        zf = zipfile.ZipFile(zip_tmp_path, "r")
    except zipfile.BadZipFile:
        errors.append({"filename": zip_name, "error": "Not a valid zip archive"})
        try:
            os.unlink(zip_tmp_path)
        except OSError:
            pass
        return

    pre_count = len(dispatched)
    bg_entries: list = []  # entries to hand to the background task
    nested_skipped: list = []  # nested archives we refuse to recurse into

    with zf:
        for info in zf.infolist():
            entry = info.filename
            # Preserve the full relative path (e.g. "persistence/tasks/System32/SilentCleanup")
            # so downstream plugin routing can use directory context to identify artifact types.
            entry_name = entry.replace("\\", "/").rstrip("/")  # normalize, drop trailing slash
            base_name = entry_name.split("/")[-1]  # basename for skip checks only
            if not base_name or entry.endswith("/") or base_name.startswith("."):
                continue
            if base_name.lower().endswith(".zip"):
                logger.info("Skipping nested zip '%s' inside '%s'", base_name, zip_name)
                nested_skipped.append(entry_name)
                continue
            if _is_auxiliary(base_name):
                logger.debug("Skipping auxiliary file '%s' in '%s'", base_name, zip_name)
                continue

            # Use the compressed size as a placeholder so the UI shows something
            # immediately; the real size is updated in the background task.
            placeholder_size = info.file_size or info.compress_size or 1

            job_id = uuid.uuid4().hex
            # MinIO key includes the full relative path so the object is addressable by path
            minio_key = f"cases/{case_id}/{job_id}/{entry_name}"

            job_svc.create_job(
                job_id, case_id, entry_name, "", source_zip=zip_name, keep_raw=keep_raw
            )
            job_svc.update_job(job_id, status="UPLOADING", size_bytes=placeholder_size)

            bg_entries.append((entry, entry_name, job_id, minio_key))

            entry_rec: dict = {
                "job_id": job_id,
                "filename": entry_name,
                "status": "UPLOADING",
                "size_bytes": placeholder_size,
                "source_zip": zip_name,
            }
            dispatched.append(entry_rec)

    if nested_skipped:
        # One per-archive note listing the nested zips we refused to recurse
        # into — previously they vanished with only a server log line.
        names = ", ".join(nested_skipped[:10])
        if len(nested_skipped) > 10:
            names += f", … (+{len(nested_skipped) - 10} more)"
        errors.append(
            {
                "filename": zip_name,
                "error": f"{len(nested_skipped)} nested archive(s) not extracted: {names}",
            }
        )

    if len(dispatched) == pre_count:
        if not errors:
            errors.append(
                {"filename": zip_name, "error": "Zip archive contained no processable files"}
            )
        try:
            os.unlink(zip_tmp_path)
        except OSError:
            pass
        return

    # Schedule extraction + upload as a background task so it runs after the response
    background_tasks.add_task(_extract_and_dispatch_bg, case_id, zip_name, zip_tmp_path, bg_entries)


# ── Chunked upload endpoint ────────────────────────────────────────────────────


@router.post("/cases/{case_id}/ingest/chunk")
async def ingest_chunk(
    case_id: str,
    upload_id: str = Form(...),
    filename: str = Form(...),
    chunk_index: int = Form(...),
    total_chunks: int = Form(...),
    chunk: UploadFile = File(...),
    keep_raw: bool = Form(False),
    background_tasks: BackgroundTasks = None,
    _case: dict = Depends(require_upload_access),
):
    """
    Receive one chunk of a large file upload.

    The client splits a file into fixed-size pieces and POSTs them sequentially.
    Each piece is appended to a per-upload temp file. When the final chunk arrives
    the assembled file is handed off to the normal ingest pipeline.

    This avoids proxy body-size limits and read timeouts entirely — each chunk
    is a small request (typically 50 MB) that completes in a few seconds.
    """
    case = _require_writable_case(case_id)

    # Sanitise upload_id so it's safe to use as a filename component
    if not re.fullmatch(r"[0-9a-f\-]{8,64}", upload_id):
        raise HTTPException(status_code=400, detail="Invalid upload_id")

    # Bounds validation — a bad index/count would otherwise silently corrupt
    # the assembled file (negative index appends anyway, total=0 never
    # finalizes, etc.).
    if not 1 <= total_chunks <= _MAX_CHUNKS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid total_chunks {total_chunks} (must be 1..{_MAX_CHUNKS})",
        )
    if not 0 <= chunk_index < total_chunks:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid chunk_index {chunk_index} (must be 0..{total_chunks - 1})",
        )

    safe_name = re.sub(r"[^\w.\-]", "_", filename)[:200]
    try:
        tmp_path = str(safe_join(_ensure_chunk_dir(), f"{upload_id}_{safe_name}"))
    except UnsafePathError:
        raise HTTPException(status_code=400, detail="Invalid filename")
    meta_path = Path(tmp_path + _CHUNK_META_SUFFIX)
    lock_path = Path(tmp_path + _CHUNK_LOCK_SUFFIX)

    loop = asyncio.get_event_loop()
    try:
        data = await chunk.read()

        # Blocking disk write (chunks can be tens of MB) — keep it off the loop.
        # The ledger write stays in the same executor call so the append and the
        # bookkeeping can't drift apart.
        def _append():
            # Being in one executor call is not mutual exclusion: this handler
            # runs in a thread pool AND behind several uvicorn workers, so two
            # requests carrying the same (upload_id, chunk_index) could both
            # read the ledger before either wrote it, both pass the duplicate
            # check, and both append — silently doubling bytes in the assembled
            # file. flock makes the whole read-check-append-write exclusive
            # across threads and processes alike.
            with open(lock_path, "a+") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                try:
                    meta = _load_chunk_meta(meta_path)
                    if chunk_index in meta["indexes"]:
                        raise _DuplicateChunk(chunk_index)
                    with open(tmp_path, "ab") as f:
                        f.write(data)
                    meta["indexes"].append(chunk_index)
                    meta["bytes"] += len(data)
                    meta_path.write_text(json.dumps(meta))
                    return meta
                finally:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

        meta = await loop.run_in_executor(None, _append)
    except _DuplicateChunk as exc:
        # Same upload_id + same chunk index — the append already happened once;
        # appending again would corrupt the assembly.
        raise HTTPException(
            status_code=409,
            detail=f"Chunk {exc.args[0]} already received for this upload_id",
        ) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to store chunk: {exc}")

    # Not the last chunk — acknowledge and wait for more
    if chunk_index < total_chunks - 1:
        return {"status": "partial", "chunk": chunk_index, "received": len(meta["indexes"])}

    # ── Final chunk — verify assembly integrity before handoff ───────────────
    missing = [i for i in range(total_chunks) if i not in meta["indexes"]]
    if missing:
        # Leave the partial assembly on disk — the client may still send the
        # missing chunk(s) and retry the final one.
        raise HTTPException(
            status_code=400,
            detail=f"Upload incomplete: {len(missing)} chunk(s) missing (first: {missing[:5]})",
        )
    size = os.path.getsize(tmp_path)
    if meta["bytes"] != size:
        raise HTTPException(
            status_code=400,
            detail=f"Assembly corrupt: ledger bytes {meta['bytes']} != file size {size}",
        )

    # Assembly is complete and verified — drop the ledger and sweep abandoned
    # uploads (older than 24h) while we're here.
    try:
        meta_path.unlink()
    except OSError:
        pass
    try:
        lock_path.unlink()
    except OSError:
        pass
    _sweep_stale_chunks()

    dispatched: list = []
    errors: list = []

    # The handoff reads the zip central directory and creates a job stub per
    # entry (2 Redis ops × N entries) — synchronous work that would stall the
    # loop for large archives. Run it in a worker thread.
    def _handoff():
        if filename.lower().endswith(".zip"):
            _handle_zip_async(
                case_id, filename, tmp_path, dispatched, errors, background_tasks, keep_raw=keep_raw
            )
        else:
            _ingest_one_async(
                case_id,
                filename,
                tmp_path,
                size,
                dispatched,
                errors,
                background_tasks,
                keep_raw=keep_raw,
            )

    try:
        await loop.run_in_executor(None, _handoff)
    except Exception as exc:
        logger.error("Failed to register chunked ingest for '%s': %s", filename, exc)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail=f"Server error: {exc}")

    if errors and not dispatched:
        raise HTTPException(status_code=400, detail=errors[0]["error"])

    response: dict = {"case_id": case_id, "jobs": dispatched}
    if errors:
        response["errors"] = errors
    return response


# ── Endpoint ───────────────────────────────────────────────────────────────────


@router.post("/cases/{case_id}/ingest")
async def ingest_files(
    case_id: str,
    files: list[UploadFile] = File(...),
    keep_raw: bool = Form(False),
    background_tasks: BackgroundTasks = None,
    _case: dict = Depends(require_upload_access),
):
    """
    Upload one or more forensics files (or zip archives) to a case and enqueue processing.

    Files are spooled to local disk immediately (fast), the HTTP response is sent at
    once with UPLOADING job IDs, and the actual MinIO transfer happens in the background.
    This prevents Traefik / proxy timeouts on large files (500 MB+).

    Status lifecycle: UPLOADING → PENDING → RUNNING → COMPLETED | FAILED
    """
    case = _require_writable_case(case_id)

    dispatched: list = []
    errors: list = []

    for upload in files:
        filename = upload.filename or "unknown"
        # The filename is client-supplied and must not reach two places raw:
        #   * the temp-file path — a '/' inside mkstemp's suffix is joined into
        #     the path, so "../../app/x" escapes the temp directory entirely;
        #   * the log — an embedded CR/LF forges whole log lines (the chunked
        #     upload path already sanitised for exactly this reason, line ~512).
        # The unsanitised name is still echoed in the JSON error payload, where
        # it is a quoted string value and cannot forge structure.
        safe_name = re.sub(r"[^\w.\-]", "_", filename)[:200] or "unknown"

        # ── Stream upload to a local temp file ────────────────────────────────
        # Uses UploadFile.read() in 4 MB chunks so the event loop is never
        # blocked for more than a few milliseconds, even for 500 MB+ files.
        # Each read() call is internally dispatched to a thread pool by
        # Starlette, keeping other requests responsive during large uploads.
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(prefix="fo_ingest_", suffix=f"_{safe_name}")
            os.close(tmp_fd)

            size = 0
            chunk_size = 4 * 1024 * 1024  # 4 MB chunks
            with open(tmp_path, "wb") as out:
                while True:
                    chunk = await upload.read(chunk_size)
                    if not chunk:
                        break
                    out.write(chunk)
                    size += len(chunk)

        except Exception as exc:
            logger.error("Cannot spool '%s' to disk: %s", safe_name, exc)
            # Clean up partial temp file if it was created
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            errors.append({"filename": filename, "error": f"Failed to receive file: {exc}"})
            continue

        try:
            if filename.lower().endswith(".zip"):
                _handle_zip_async(
                    case_id,
                    filename,
                    tmp_path,
                    dispatched,
                    errors,
                    background_tasks,
                    keep_raw=keep_raw,
                )
            else:
                _ingest_one_async(
                    case_id,
                    filename,
                    tmp_path,
                    size,
                    dispatched,
                    errors,
                    background_tasks,
                    keep_raw=keep_raw,
                )
        except Exception as exc:
            logger.error("Failed to register ingest job for '%s': %s", safe_name, exc)
            errors.append({"filename": filename, "error": f"Server error: {exc}"})
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if not dispatched and not errors:
        raise HTTPException(status_code=400, detail="No valid files uploaded")

    if not dispatched and errors:
        raise HTTPException(
            status_code=400,
            detail={"message": "All files failed to ingest", "errors": errors},
            headers={"X-Ingest-Errors": str(len(errors))},
        )

    response: dict = {"case_id": case_id, "jobs": dispatched}
    if errors:
        response["errors"] = errors
    return response


# ── Reingest ──────────────────────────────────────────────────────────────────


class ReingestRequest(BaseModel):
    plugin: str | None = None  # e.g. "access_log", "syslog", "log2timeline"


@router.post("/cases/{case_id}/jobs/{job_id}/reingest")
def reingest_job(
    case_id: str,
    job_id: str,
    req: ReingestRequest = ReingestRequest(),
    _case: dict = Depends(require_case_access),
):
    """
    Re-run ingestion for an existing job (COMPLETED, FAILED, or SKIPPED).

    Optionally specify a plugin name to override auto-detection — useful when
    the automatic parser chose the wrong ingester (e.g. json_file instead of
    access_log for a rotated log file).

    The job is reset to PENDING and re-dispatched on the ingest queue.
    Previous timeline events are NOT removed — run a case-level cleanup first
    if you need a clean re-ingest.
    """
    from services.celery_dispatch import dispatch_ingest

    case = _require_writable_case(case_id)

    job = job_svc.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id!r} not found")
    if job.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail="Job does not belong to this case")

    # Guard against double dispatch: a job already queued or in flight must not
    # be re-enqueued — wait for it to reach a terminal state first.
    if job.get("status") in ("PENDING", "QUEUED", "UPLOADING", "RUNNING"):
        raise HTTPException(
            status_code=409,
            detail=f"Job is still active (status: {job.get('status')}) — cannot reingest yet",
        )

    minio_key = job.get("minio_object_key", "")
    if not minio_key:
        raise HTTPException(
            status_code=400,
            detail=(
                "Job has no stored file — cannot reingest. If this job came from an "
                "S3 import and failed before upload completed, use "
                "POST /jobs/{job_id}/retry instead (retry restarts the S3 transfer "
                "phase; reingest only re-parses an already-stored file)."
            ),
        )

    filename = job.get("original_filename", "")

    job_svc.reset_job_for_retry(job_id, plugin_hint=req.plugin or "")

    try:
        dispatch_ingest(job_id, case_id, minio_key, filename)
    except Exception as exc:
        job_svc.update_job(job_id, status="FAILED", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Dispatch failed: {exc}")

    return {
        "job_id": job_id,
        "status": "PENDING",
        "plugin_hint": req.plugin or "",
        "message": "Job reset and re-queued.",
    }


# ── Cancel all pending/running jobs ──────────────────────────────────────────


@router.post("/cases/{case_id}/ingest/cancel")
def cancel_case_ingestion(case_id: str, _case: dict = Depends(require_case_access)):
    """
    Cancel all PENDING and RUNNING ingest jobs for a case.

    PENDING jobs will be skipped by the processor (cancellation check at task
    start). RUNNING jobs that are mid-processing will complete, but their
    status will reflect COMPLETED normally — interrupting active I/O mid-stream
    is not safe without checkpointing.
    """
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Iterate ALL job IDs (same pattern as delete_all_case_jobs) — the old code
    # used list_case_jobs()'s default 500-record page, leaving older
    # PENDING/UPLOADING jobs running on big cases.
    active_statuses = {"PENDING", "UPLOADING"}
    cancelled = []
    for jid in job_svc.list_case_job_ids(case_id):
        job = job_svc.get_job(jid)
        if not job:
            continue
        if job.get("status") in active_statuses:
            job_svc.update_job(
                jid,
                status="CANCELLED",
                completed_at=datetime.now(UTC).isoformat(),
                error="Cancelled by user",
            )
            cancelled.append(jid)

    return {
        "case_id": case_id,
        "cancelled": len(cancelled),
        "job_ids": cancelled,
    }


# Statuses that mean a job is still doing work — while any exist the stream
# keeps emitting; once none remain we send a final `done` event and close.
_ACTIVE_STATUSES = ("PENDING", "QUEUED", "UPLOADING", "RUNNING")


@router.get("/cases/{case_id}/ingest/stream")
async def ingest_progress_stream(
    case_id: str, _case: dict = Depends(require_case_access)
):
    """Server-Sent Events stream of per-case ingest progress.

    Emits a `data:` event with the live status tally every ~2s until no job is
    active, then a final `event: done`. Lets the UI show real progress instead
    of blind client-side polling. EventSource cannot set headers, so the token
    is supplied via ?_token= (handled by the standard auth dependency).
    """

    async def _gen():
        # Hard cap so a wedged case can't hold a connection forever (~20 min).
        for _ in range(600):
            counts = job_svc.status_counts_for_case(case_id)
            total = sum(counts.values())
            done = sum(v for k, v in counts.items() if k not in _ACTIVE_STATUSES)
            active = total - done
            payload = {
                "case_id": case_id,
                "counts": counts,
                "total": total,
                "done": done,
                "active": active,
            }
            yield f"data: {json.dumps(payload)}\n\n"
            if total > 0 and active == 0:
                yield "event: done\ndata: {}\n\n"
                return
            await asyncio.sleep(2)
        # Timed out with work still pending — tell the client to fall back.
        yield "event: timeout\ndata: {}\n\n"

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
