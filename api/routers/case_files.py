"""
Case file viewer — browse and search the raw files stored in MinIO for a case.

Endpoints:
  GET  /cases/{case_id}/files                          — list all ingested files
  GET  /cases/{case_id}/files/{job_id}/content         — read a readable file's text content
  GET  /cases/{case_id}/files/{job_id}/download        — stream the full stored file
  GET  /cases/{case_id}/files/{job_id}/extract?member= — extract one member from an archive
  POST /cases/{case_id}/files/search                   — search within readable file content
  GET  /cases/{case_id}/disk-images                    — list disk-image jobs
  GET  /cases/{case_id}/disk-images/{job_id}/browse    — browse directory in indexed image
"""

from __future__ import annotations

import logging
import mimetypes
import os
import re
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import quote

from auth.dependencies import require_case_access
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from services import elasticsearch as es
from services import jobs as job_svc
from services import storage

from config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["case-files"])

# ── Readable extension whitelist ──────────────────────────────────────────────
_READABLE_EXTS = {
    ".json",
    ".jsonl",
    ".ndjson",
    ".xml",
    ".plist",
    ".yaml",
    ".yml",
    ".txt",
    ".log",
    ".csv",
    ".tsv",
    ".ps1",
    ".bat",
    ".vbs",
    ".js",
    ".conf",
    ".cfg",
    ".ini",
    ".toml",
    ".md",
    ".rst",
    ".html",
    ".htm",
    ".py",
    ".sh",
}

_DISK_IMAGE_EXTS = {
    ".dd",
    ".img",
    ".raw",
    ".001",
    ".e01",
    ".ex01",
    ".vmdk",
    ".vhd",
    ".vhdx",
}

_MAX_VIEW_BYTES = 5 * 1024 * 1024  # 5 MB
_MAX_SEARCH_BYTES = 2 * 1024 * 1024  # 2 MB per file during search

# Decompression-bomb cap for single-member extraction. A crafted archive can
# declare a small member while inflating to gigabytes, so we both reject members
# whose *declared* size exceeds the cap and abort mid-copy once the *actual*
# extracted bytes cross it. Configurable via env; default 2 GiB.
_MAX_EXTRACT_MEMBER_BYTES = int(
    os.getenv("MAX_EXTRACT_MEMBER_BYTES", str(2 * 1024**3))
)


def _bounded_copy(src, dst, limit: int) -> int:
    """Stream src→dst in 1 MiB chunks, aborting if more than ``limit`` bytes are
    read. Mirrors ``routers.ingest._bounded_copy`` — defends against archive
    members that lie about their uncompressed size (decompression bombs)."""
    written = 0
    while True:
        chunk = src.read(1024 * 1024)
        if not chunk:
            break
        written += len(chunk)
        if written > limit:
            raise ValueError(f"member exceeds extraction size cap ({limit} bytes)")
        dst.write(chunk)
    return written


def _content_disposition(filename: str) -> str:
    """
    Build a Content-Disposition header value that handles non-ASCII filenames.

    Sends both an ASCII fallback (filename=) and an RFC 5987 UTF-8 encoded
    version (filename*=) so all browsers get the correct name without raising
    Python's UnicodeEncodeError when the header is serialised as latin-1.
    """
    ascii_name = filename.encode("ascii", errors="replace").decode("ascii").replace('"', '\\"')
    utf8_name = quote(filename, safe="")
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{utf8_name}"


def _is_readable(filename: str) -> bool:
    return Path(filename).suffix.lower() in _READABLE_EXTS


def _is_disk_image(filename: str) -> bool:
    return Path(filename).suffix.lower() in _DISK_IMAGE_EXTS


def _file_category(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext in _DISK_IMAGE_EXTS:
        return "disk_image"
    if ext in _READABLE_EXTS:
        return "text"
    if ext in {".pcap", ".pcapng", ".cap"}:
        return "pcap"
    if ext in {".evtx", ".evt"}:
        return "evtx"
    if ext in {".sqlite", ".db", ".sqlite3", ".db3", ".esedb", ".edb"}:
        return "database"
    if ext in {".exe", ".dll", ".sys", ".so", ".elf"}:
        return "binary"
    return "binary"


# ── List files ────────────────────────────────────────────────────────────────


@router.get("/cases/{case_id}/files")
def list_case_files(case_id: str, _case: dict = Depends(require_case_access)):
    """List all files ingested into a case with readability metadata."""
    jobs = job_svc.list_case_jobs(case_id)
    files = []
    for job in jobs:
        fname = job.get("original_filename", "")
        files.append(
            {
                "job_id": job.get("job_id"),
                "filename": fname,
                "status": job.get("status"),
                "size_bytes": job.get("size_bytes", 0),
                "events_indexed": job.get("events_indexed", 0),
                "plugin_used": job.get("plugin_used", ""),
                "plugin_hint": job.get("plugin_hint", ""),
                "created_at": job.get("created_at", ""),
                "category": _file_category(fname),
                "is_readable": _is_readable(fname),
                "is_disk_image": _is_disk_image(fname),
                "source_zip": job.get("source_zip", ""),
            }
        )
    return {"case_id": case_id, "files": files, "total": len(files)}


# ── Download raw file ────────────────────────────────────────────────────────


def _storage_http_error(minio_key: str, exc: Exception) -> HTTPException:
    """Map a typed storage error to a precise HTTP status."""
    if isinstance(exc, storage.ObjectNotFound):
        logger.warning("Object missing for %s: %s", minio_key, exc)
        return HTTPException(status_code=404, detail="Stored object no longer exists")
    if isinstance(exc, storage.StorageUnavailable):
        logger.error("Storage unavailable reading %s: %s", minio_key, exc)
        return HTTPException(status_code=503, detail="Storage backend unavailable")
    logger.error("Storage read error for %s: %s", minio_key, exc)
    return HTTPException(status_code=502, detail="Storage read error")


def _minio_stream(minio_key: str):
    """Generator that yields chunks directly from MinIO — no full-file RAM buffer."""
    yield from storage.stream_object(minio_key)


@router.get("/cases/{case_id}/files/{job_id}/download")
def download_file(
    case_id: str, job_id: str, _case: dict = Depends(require_case_access)
):
    """
    Stream the original stored file as a browser download.

    Auth via ?_token= query param (same pattern as CSV export) so the browser
    can trigger the download directly without AJAX.
    """
    job = job_svc.get_job(job_id)
    if not job or job.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail="File not found")

    minio_key = job.get("minio_object_key", "")
    if not minio_key:
        raise HTTPException(status_code=404, detail="File not yet in storage")

    fname = job.get("original_filename", "download")
    content_type = mimetypes.guess_type(fname)[0] or "application/octet-stream"

    # Pre-flight stat so a missing/unreachable object surfaces a precise HTTP
    # status BEFORE the streaming response headers are committed.
    try:
        storage.stat_object(minio_key)
    except storage.StorageError as exc:
        raise _storage_http_error(minio_key, exc) from exc

    return StreamingResponse(
        _minio_stream(minio_key),
        media_type=content_type,
        headers={"Content-Disposition": _content_disposition(fname)},
    )


# ── Extract single archive member ────────────────────────────────────────────


@router.get("/cases/{case_id}/files/{job_id}/extract")
def extract_archive_member(
    case_id: str,
    job_id: str,
    member: str = Query(..., description="Relative path of the member inside the archive"),
    _case: dict = Depends(require_case_access),
):
    """
    Extract and stream one member from an archived source file stored in MinIO.

    Used by EventDetail when the event was produced from a file inside a ZIP or
    TAR archive — in that case event.raw.archive_member holds the member path
    and this endpoint serves the correct binary rather than the outer archive.
    """
    job = job_svc.get_job(job_id)
    if not job or job.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail="File not found")

    minio_key = job.get("minio_object_key", "")
    if not minio_key:
        raise HTTPException(status_code=404, detail="File not yet in storage")

    # Sanitise member path — prevent path traversal
    norm_member = member.replace("\\", "/").strip("/")
    if not norm_member or ".." in norm_member.split("/"):
        raise HTTPException(status_code=400, detail="Invalid member path")
    member_name = norm_member.split("/")[-1]

    fname = job.get("original_filename", "").lower()

    # Stream the (potentially large) archive object to a temp file on disk rather
    # than buffering the whole thing in RAM. zipfile/tarfile both need random
    # access, so a disk-backed handle bounds memory while keeping seek support.
    try:
        archive_fd, archive_path = tempfile.mkstemp(prefix="fo_extract_arc_")
        try:
            with os.fdopen(archive_fd, "wb") as arc:
                for chunk in storage.stream_object(minio_key):
                    arc.write(chunk)
        except storage.StorageError:
            os.unlink(archive_path)
            raise
    except storage.StorageError as exc:
        raise _storage_http_error(minio_key, exc) from exc

    # Extract the requested member into its own temp file with a running byte cap,
    # so a member lying about its declared size is aborted mid-copy.
    member_fd, member_path = tempfile.mkstemp(prefix="fo_extract_mem_")
    os.close(member_fd)
    found = False
    try:
        cap = _MAX_EXTRACT_MEMBER_BYTES

        # ── ZIP ───────────────────────────────────────────────────────────────
        if fname.endswith(".zip"):
            try:
                with zipfile.ZipFile(archive_path) as zf:
                    info = None
                    for zi in zf.infolist():
                        if zi.filename.replace("\\", "/").strip("/") == norm_member:
                            info = zi
                            break
                    if info is None:
                        for zi in zf.infolist():
                            if Path(zi.filename).name == member_name:
                                info = zi
                                break
                    if info is not None:
                        declared = getattr(info, "file_size", 0) or 0
                        if declared > cap:
                            raise HTTPException(
                                status_code=413,
                                detail=f"Member too large to extract "
                                f"({declared} bytes > cap {cap})",
                            )
                        with zf.open(info) as src, open(member_path, "wb") as dst:
                            _bounded_copy(src, dst, cap)
                        found = True
            except zipfile.BadZipFile as exc:
                raise HTTPException(status_code=422, detail=f"Bad ZIP: {exc}")

        # ── TAR family (.tar, .tgz, .tar.gz, …) ────────────────────────────────
        else:
            try:
                with tarfile.open(archive_path) as tf:
                    match = None
                    for m in tf.getmembers():
                        if not m.isfile():
                            continue
                        if m.name.replace("\\", "/").strip("/") == norm_member:
                            match = m
                            break
                    if match is None:
                        for m in tf.getmembers():
                            if m.isfile() and Path(m.name).name == member_name:
                                match = m
                                break
                    if match is not None:
                        declared = getattr(match, "size", 0) or 0
                        if declared > cap:
                            raise HTTPException(
                                status_code=413,
                                detail=f"Member too large to extract "
                                f"({declared} bytes > cap {cap})",
                            )
                        src = tf.extractfile(match)
                        if src is not None:
                            with src, open(member_path, "wb") as dst:
                                _bounded_copy(src, dst, cap)
                            found = True
            except tarfile.TarError as exc:
                raise HTTPException(status_code=422, detail=f"TAR error: {exc}")
    except ValueError as exc:
        # Raised by _bounded_copy when the actual bytes exceed the cap.
        os.unlink(member_path)
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except BaseException:
        os.unlink(member_path)
        raise
    finally:
        os.unlink(archive_path)

    if not found:
        os.unlink(member_path)
        raise HTTPException(
            status_code=404,
            detail=f"Member '{norm_member}' not found in archive",
        )

    content_type = mimetypes.guess_type(member_name)[0] or "application/octet-stream"

    def _stream_member():
        try:
            with open(member_path, "rb") as fh:
                while True:
                    chunk = fh.read(1024 * 1024)
                    if not chunk:
                        break
                    yield chunk
        finally:
            try:
                os.unlink(member_path)
            except OSError:
                pass

    return StreamingResponse(
        _stream_member(),
        media_type=content_type,
        headers={"Content-Disposition": _content_disposition(member_name)},
    )


# ── Read file content ─────────────────────────────────────────────────────────


@router.get("/cases/{case_id}/files/{job_id}/content")
def get_file_content(
    case_id: str, job_id: str, _case: dict = Depends(require_case_access)
):
    """
    Return the text content of a readable file stored in MinIO.
    HTTP 415 for binary/unreadable files, HTTP 413 if file exceeds 5 MB.
    """
    job = job_svc.get_job(job_id)
    if not job or job.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail="File not found")

    fname = job.get("original_filename", "")
    if not _is_readable(fname):
        raise HTTPException(
            status_code=415,
            detail=f"'{fname}' is not a readable text type. "
            f"Supported: {', '.join(sorted(_READABLE_EXTS))}",
        )

    minio_key = job.get("minio_object_key", "")
    if not minio_key:
        raise HTTPException(status_code=404, detail="File not yet in storage")

    # Pre-flight stat so an oversized object is rejected (413) BEFORE any bytes
    # are pulled into the pod — avoids buffering a multi-GB file just to refuse it.
    try:
        st = storage.stat_object(minio_key)
    except storage.StorageError as exc:
        raise _storage_http_error(minio_key, exc) from exc

    if st.size > _MAX_VIEW_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large to view ({st.size // 1024} KB > {_MAX_VIEW_BYTES // 1024} KB). Download instead.",
        )

    # Size is bounded (<= _MAX_VIEW_BYTES); stream the chunks and join, so RAM
    # use is capped by the view limit rather than the raw object size.
    try:
        raw = b"".join(storage.stream_object(minio_key))
    except storage.StorageError as exc:
        raise _storage_http_error(minio_key, exc) from exc

    content = raw.decode("utf-8", errors="replace")
    return {
        "job_id": job_id,
        "filename": fname,
        "size_bytes": len(raw),
        "content": content,
    }


# ── Search within files ───────────────────────────────────────────────────────


class FileSearchRequest(BaseModel):
    query: str
    regex: bool = False


@router.post("/cases/{case_id}/files/search")
def search_file_contents(
    case_id: str, body: FileSearchRequest, _case: dict = Depends(require_case_access)
):
    """
    Full-text search within all readable stored files for a case.
    Returns line-level context snippets (±3 lines around each match).
    """
    if not body.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")
    # Cap the pattern length — a user-supplied regex (body.regex=True) is compiled
    # directly, so a huge/crafted pattern is the main ReDoS lever. Bounding length
    # keeps catastrophic backtracking off the table for case-file scans.
    if len(body.query) > 500:
        raise HTTPException(status_code=400, detail="Query too long (max 500 chars)")

    try:
        flags = re.IGNORECASE
        pattern = re.compile(body.query if body.regex else re.escape(body.query), flags)
    except re.error as exc:
        raise HTTPException(status_code=400, detail=f"Invalid regex: {exc}")

    jobs = job_svc.list_case_jobs(case_id)
    results = []
    files_searched = 0

    for job in jobs:
        if job.get("status") != "COMPLETED":
            continue
        fname = job.get("original_filename", "")
        if not _is_readable(fname):
            continue

        minio_key = job.get("minio_object_key", "")
        if not minio_key:
            continue

        files_searched += 1

        # Stat first so an oversized file is reported skipped without ever
        # pulling its bytes into the pod.
        try:
            st = storage.stat_object(minio_key)
        except storage.StorageUnavailable as exc:
            # Backend outage — don't silently return partial search results.
            raise HTTPException(
                status_code=503, detail="Storage backend unavailable"
            ) from exc
        except storage.StorageError as exc:
            # Missing/corrupt single object — skip it and keep searching.
            logger.warning("Skipping '%s' — read failed: %s", fname, exc)
            continue

        if st.size > _MAX_SEARCH_BYTES:
            results.append(
                {
                    "job_id": job.get("job_id"),
                    "filename": fname,
                    "skipped": True,
                    "reason": f"File too large ({st.size // 1024} KB)",
                    "matches": [],
                }
            )
            continue

        # Size is bounded (<= _MAX_SEARCH_BYTES); stream and join so RAM stays
        # capped by the search limit rather than the raw object size.
        try:
            raw = b"".join(storage.stream_object(minio_key))
        except storage.StorageUnavailable as exc:
            raise HTTPException(
                status_code=503, detail="Storage backend unavailable"
            ) from exc
        except storage.StorageError as exc:
            logger.warning("Skipping '%s' — read failed: %s", fname, exc)
            continue

        lines = raw.decode("utf-8", errors="replace").splitlines()
        matches = []
        for lineno, line in enumerate(lines):
            if pattern.search(line):
                ctx_start = max(0, lineno - 3)
                ctx_end = min(len(lines), lineno + 4)
                matches.append(
                    {
                        "line": lineno + 1,
                        "text": line,
                        "context": "\n".join(lines[ctx_start:ctx_end]),
                    }
                )
            if len(matches) >= 200:
                break

        if matches:
            results.append(
                {
                    "job_id": job.get("job_id"),
                    "filename": fname,
                    "skipped": False,
                    "match_count": len(matches),
                    "matches": matches,
                }
            )

    return {
        "case_id": case_id,
        "query": body.query,
        "files_searched": files_searched,
        "files_matched": len(results),
        "results": results,
    }


# ── Disk image list ───────────────────────────────────────────────────────────


@router.get("/cases/{case_id}/disk-images")
def list_disk_images(case_id: str, _case: dict = Depends(require_case_access)):
    """List all disk image files ingested into a case."""
    jobs = job_svc.list_case_jobs(case_id)
    images = [
        {
            "job_id": job.get("job_id"),
            "filename": job.get("original_filename", ""),
            "status": job.get("status"),
            "events_indexed": job.get("events_indexed", 0),
            "created_at": job.get("created_at", ""),
            "plugin_used": job.get("plugin_used", ""),
        }
        for job in jobs
        if _is_disk_image(job.get("original_filename", ""))
    ]
    return {"case_id": case_id, "disk_images": images, "total": len(images)}


# ── Disk image directory browser ──────────────────────────────────────────────


@router.get("/cases/{case_id}/disk-images/{job_id}/browse")
def browse_disk_image(
    case_id: str,
    job_id: str,
    path: str = Query("/", description="Directory path within the image"),
    size: int = Query(500, le=2000),
    _case: dict = Depends(require_case_access),
):
    """
    Browse the filesystem of an indexed disk image.

    The diskimage plugin indexes every file-system entry as an ES event with
    artifact_type=diskimage. This endpoint queries those events by parent path
    to return directory contents without re-mounting the image.
    """
    job = job_svc.get_job(job_id)
    if not job or job.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail="Disk image job not found")

    browse_path = path.rstrip("/") + "/"
    if browse_path == "//":
        browse_path = "/"

    query = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"artifact_type": "diskimage"}},
                    {"term": {"ingest_job_id": job_id}},
                    {"term": {"diskimage.parent.keyword": browse_path}},
                ]
            }
        },
        "sort": [
            {"diskimage.is_dir": "desc"},
            {"diskimage.name.keyword": "asc"},
        ],
        "size": size,
        "_source": [
            "diskimage.name",
            "diskimage.path",
            "diskimage.parent",
            "diskimage.size",
            "diskimage.is_dir",
            "diskimage.mtime",
            "diskimage.atime",
            "diskimage.ctime",
            "diskimage.inode",
        ],
    }

    try:
        result = es._request("POST", f"/fo-case-{case_id}-diskimage/_search", query)
    except Exception as exc:
        logger.warning("ES browse failed for %s/%s: %s", case_id, job_id, exc)
        return {
            "case_id": case_id,
            "job_id": job_id,
            "path": browse_path,
            "entries": [],
            "total": 0,
        }

    hits = result.get("hits", {})
    entries = []
    for h in hits.get("hits", []):
        src = h["_source"].get("diskimage", {})
        entries.append(
            {
                "name": src.get("name", ""),
                "path": src.get("path", ""),
                "parent": src.get("parent", ""),
                "size": src.get("size", 0),
                "is_dir": src.get("is_dir", False),
                "mtime": src.get("mtime", ""),
                "inode": src.get("inode", 0),
            }
        )

    return {
        "case_id": case_id,
        "job_id": job_id,
        "filename": job.get("original_filename", ""),
        "path": browse_path,
        "entries": entries,
        "total": hits.get("total", {}).get("value", 0),
    }
