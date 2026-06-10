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

import io
import logging
import mimetypes
import re
import tarfile
import zipfile
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from services import elasticsearch as es
from services import jobs as job_svc
from services import storage
from services.cases import get_case

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
def list_case_files(case_id: str):
    """List all files ingested into a case with readability metadata."""
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")

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


def _minio_stream(minio_key: str):
    """Generator that yields chunks directly from MinIO — no full-file RAM buffer."""
    client = storage.get_minio()
    response = client.get_object(settings.MINIO_BUCKET, minio_key)
    try:
        yield from response
    finally:
        try:
            response.close()
            response.release_conn()
        except Exception:
            pass


@router.get("/cases/{case_id}/files/{job_id}/download")
def download_file(case_id: str, job_id: str):
    """
    Stream the original stored file as a browser download.

    Auth via ?_token= query param (same pattern as CSV export) so the browser
    can trigger the download directly without AJAX.
    """
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")

    job = job_svc.get_job(job_id)
    if not job or job.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail="File not found")

    minio_key = job.get("minio_object_key", "")
    if not minio_key:
        raise HTTPException(status_code=404, detail="File not yet in storage")

    fname = job.get("original_filename", "download")
    content_type = mimetypes.guess_type(fname)[0] or "application/octet-stream"

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
):
    """
    Extract and stream one member from an archived source file stored in MinIO.

    Used by EventDetail when the event was produced from a file inside a ZIP or
    TAR archive — in that case event.raw.archive_member holds the member path
    and this endpoint serves the correct binary rather than the outer archive.
    """
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")

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

    try:
        raw = storage.download_fileobj(minio_key)
    except Exception as exc:
        logger.error("Failed to download %s: %s", minio_key, exc)
        raise HTTPException(status_code=502, detail=f"Storage read error: {exc}")

    fname = job.get("original_filename", "").lower()
    member_bytes: bytes | None = None

    # ── ZIP ───────────────────────────────────────────────────────────────────
    if fname.endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                # Exact path match (normalised to forward slashes)
                for n in zf.namelist():
                    if n.replace("\\", "/").strip("/") == norm_member:
                        member_bytes = zf.read(n)
                        break
                # Fallback: filename-only match (handles path differences)
                if member_bytes is None:
                    for n in zf.namelist():
                        if Path(n).name == member_name:
                            member_bytes = zf.read(n)
                            break
        except zipfile.BadZipFile as exc:
            raise HTTPException(status_code=422, detail=f"Bad ZIP: {exc}")

    # ── TAR family (.tar, .tgz, .tar.gz, …) ──────────────────────────────────
    else:
        try:
            with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
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
                    f = tf.extractfile(match)
                    if f:
                        member_bytes = f.read()
        except tarfile.TarError as exc:
            raise HTTPException(status_code=422, detail=f"TAR error: {exc}")

    if member_bytes is None:
        raise HTTPException(
            status_code=404,
            detail=f"Member '{norm_member}' not found in archive",
        )

    content_type = mimetypes.guess_type(member_name)[0] or "application/octet-stream"

    return StreamingResponse(
        iter([member_bytes]),
        media_type=content_type,
        headers={"Content-Disposition": _content_disposition(member_name)},
    )


# ── Read file content ─────────────────────────────────────────────────────────


@router.get("/cases/{case_id}/files/{job_id}/content")
def get_file_content(case_id: str, job_id: str):
    """
    Return the text content of a readable file stored in MinIO.
    HTTP 415 for binary/unreadable files, HTTP 413 if file exceeds 5 MB.
    """
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")

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

    try:
        raw = storage.download_fileobj(minio_key)
    except Exception as exc:
        logger.error("Failed to download %s: %s", minio_key, exc)
        raise HTTPException(status_code=502, detail=f"Storage read error: {exc}")

    if len(raw) > _MAX_VIEW_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large to view ({len(raw) // 1024} KB > {_MAX_VIEW_BYTES // 1024} KB). Download instead.",
        )

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
def search_file_contents(case_id: str, body: FileSearchRequest):
    """
    Full-text search within all readable stored files for a case.
    Returns line-level context snippets (±3 lines around each match).
    """
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")

    if not body.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")

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

        try:
            raw = storage.download_fileobj(minio_key)
        except Exception as exc:
            logger.warning("Skipping '%s' — read failed: %s", fname, exc)
            continue

        if len(raw) > _MAX_SEARCH_BYTES:
            results.append(
                {
                    "job_id": job.get("job_id"),
                    "filename": fname,
                    "skipped": True,
                    "reason": f"File too large ({len(raw) // 1024} KB)",
                    "matches": [],
                }
            )
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
def list_disk_images(case_id: str):
    """List all disk image files ingested into a case."""
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")

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
):
    """
    Browse the filesystem of an indexed disk image.

    The diskimage plugin indexes every file-system entry as an ES event with
    artifact_type=diskimage. This endpoint queries those events by parent path
    to return directory contents without re-mounting the image.
    """
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")

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
