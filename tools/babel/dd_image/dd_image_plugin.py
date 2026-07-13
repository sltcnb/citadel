"""
DD / raw disk-image plugin — minimal forensic extraction.

Workflow for each uploaded disk image (.dd / .img / .raw):
  1. Open with pytsk3 (The Sleuth Kit Python bindings).
  2. Enumerate all partitions.  For each allocated partition, walk the
     filesystem tree and yield one "dd_file" event per file (the file list
     the analyst sees immediately).
  3. For every non-deleted file within the size limit, extract it to a temp
     file, upload to MinIO, and dispatch a child ingest job so that existing
     parsers (EVTX, MFT, registry, LNK, …) process its contents automatically.
  4. If photorec is available, carve unallocated space and dispatch child jobs
     for each recovered file too (artifact_type="dd_carved").

Limits:
  - Files larger than DD_MAX_EXTRACT_MB env var (default 500 MB) are listed
    but not extracted — they are too large for the existing parsers.
  - Zero-byte files are listed only.
  - Extraction stops streaming if a read returns empty (corrupt image).
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import pytsk3

    _TSK_OK = True
except ImportError:
    _TSK_OK = False

try:
    from minio import Minio as _MinioClient

    _MINIO_SDK_OK = True
except ImportError:
    _MinioClient = None  # type: ignore
    _MINIO_SDK_OK = False

import redis as _redis_lib
from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

# ── tunables ──────────────────────────────────────────────────────────────────

_JOB_TTL = 7 * 24 * 3600  # 7 days — matches API
_BUCKET = os.environ.get("MINIO_BUCKET", "forensics-cases")
_MAX_BYTES = int(os.environ.get("DD_MAX_EXTRACT_MB", "500")) * 1024 * 1024
_CHUNK = 1024 * 1024  # 1 MB read chunks
# Upper bound for a single read() when the caller passes n < 0 ("read all
# remaining"). Prevents pulling a whole multi-GB image into RAM in one call;
# callers that want everything simply loop until read() returns b"".
_MAX_READ_ALL = int(os.environ.get("DD_MAX_READ_ALL_MB", "64")) * 1024 * 1024
_SKIP_NAMES = frozenset([".", "..", "$OrphanFiles"])


# ── S3RangeReader ─────────────────────────────────────────────────────────────


class S3RangeReader:
    """Seekable, file-like wrapper around an S3 object.

    Translates seek()/read() calls into HTTP Range-GET requests so that
    pytsk3 / libewf can parse disk images directly from S3 without a
    full download to disk or MinIO.

    Usage::
        client = Minio(endpoint, access_key=..., secret_key=..., secure=True)
        reader = S3RangeReader(client, "my-bucket", "evidence/disk.dd")
        img    = pytsk3.Img_Info(url="", fileobj=reader)

    Transfer cost: one Range-GET per read() call.  For a full filesystem
    index pass on a 500 GB image, pytsk3 typically issues < 50 MB of reads
    (MBR/GPT + superblocks + inode tables only).  Individual file extraction
    is a single range fetch for exactly the file's byte range.
    """

    def __init__(self, client: _MinioClient, bucket: str, key: str) -> None:
        self._client = client
        self._bucket = bucket
        self._key = key
        self._pos = 0
        stat = client.stat_object(bucket, key)
        self._size = stat.size

    # ── io protocol ──────────────────────────────────────────────────────────

    def read(self, n: int = -1) -> bytes:
        if self._pos >= self._size:
            return b""
        remaining = self._size - self._pos
        # n < 0 means "read all remaining" — cap it to a bounded chunk so a
        # single call can't materialise a multi-GB image in RAM. Callers loop
        # until read() returns b"" to consume the whole object.
        length = min(remaining, _MAX_READ_ALL) if n < 0 else min(n, remaining)
        resp = None
        try:
            resp = self._client.get_object(
                self._bucket,
                self._key,
                offset=self._pos,
                length=length,
            )
            data = resp.read()
        finally:
            if resp is not None:
                try:
                    resp.close()
                    resp.release_conn()
                except Exception:
                    pass
        self._pos += len(data)
        return data

    def seek(self, pos: int, whence: int = 0) -> int:
        if whence == 0:
            self._pos = pos
        elif whence == 1:
            self._pos += pos
        elif whence == 2:
            self._pos = self._size + pos
        self._pos = max(0, min(self._pos, self._size))
        return self._pos

    def tell(self) -> int:
        return self._pos

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def __len__(self) -> int:
        return self._size


# ── low-level helpers ─────────────────────────────────────────────────────────


def _minio() -> _MinioClient:
    return _MinioClient(
        os.environ.get("MINIO_ENDPOINT", "minio:9000"),
        access_key=os.environ.get("MINIO_ACCESS_KEY", ""),
        secret_key=os.environ.get("MINIO_SECRET_KEY", ""),
        secure=os.environ.get("MINIO_SECURE", "false").lower() == "true",
    )


def _redis() -> _redis_lib.Redis:
    from citadel_contracts import redis_url_with_auth  # noqa: PLC0415

    return _redis_lib.Redis.from_url(
        redis_url_with_auth(os.environ.get("REDIS_URL", "redis://redis:6379/0")),
        decode_responses=True,
    )


def _iso(unix_ts: int | None) -> str:
    """Convert a Unix timestamp to ISO-8601 UTC string, or '' on failure."""
    if not unix_ts or unix_ts <= 0:
        return ""
    try:
        return datetime.fromtimestamp(unix_ts, tz=UTC).isoformat()
    except (OSError, OverflowError, ValueError):
        return ""


def _is_disk_image(path: Path) -> bool:
    """Heuristic: look for MBR 0x55AA signature or GPT 'EFI PART' magic."""
    try:
        with open(path, "rb") as fh:
            sector0 = fh.read(512)
            if len(sector0) < 512:
                return False
            if struct.unpack_from("<H", sector0, 510)[0] == 0x55AA:
                return True
            fh.seek(512)
            gpt = fh.read(8)
            if gpt == b"EFI PART":
                return True
    except OSError:
        pass
    return False


def _is_bitlocker_volume(path: str, offset_bytes: int) -> bool:
    """Return True if the partition at *offset_bytes* is BitLocker-encrypted.

    BitLocker replaces the NTFS OEM ID (bytes 3-10 of the boot sector) with
    the string '-FVE-FS-' (Full Volume Encryption File System).
    """
    try:
        with open(path, "rb") as fh:
            fh.seek(offset_bytes + 3)
            return fh.read(8) == b"-FVE-FS-"
    except OSError:
        return False


def _decrypt_bitlocker(img_path: str, offset_bytes: int, recovery_key: str, tmp_dir: Path) -> Path:
    """Decrypt a BitLocker partition into a flat image file via dislocker-file.

    Writes a virtual plaintext image to *tmp_dir* without needing a loop
    device, kernel modules, or root-level mounts.
    """
    out = tmp_dir / f"decrypted_{offset_bytes}.img"
    subprocess.run(
        [
            "dislocker-file",
            "-V",
            img_path,
            "-O",
            str(offset_bytes),
            "-p",
            recovery_key,
            "--",
            str(out),
        ],
        check=True,
        timeout=600,
        capture_output=True,
    )
    return out


def _register_child_job(
    r: _redis_lib.Redis,
    job_id: str,
    case_id: str,
    filename: str,
    minio_key: str,
    parent_job_id: str,
) -> None:
    r.hset(
        f"job:{job_id}",
        mapping={
            "job_id": job_id,
            "case_id": case_id,
            "status": "PENDING",
            "original_filename": filename,
            "minio_object_key": minio_key,
            "events_indexed": "0",
            "error": "",
            "plugin_used": "",
            "plugin_stats": "{}",
            "created_at": datetime.now(UTC).isoformat(),
            "started_at": "",
            "completed_at": "",
            "task_id": "",
            # source_zip repurposed to track which DD job spawned this child
            "source_zip": parent_job_id,
        },
    )
    r.expire(f"job:{job_id}", _JOB_TTL)


def _dispatch(job_id: str, case_id: str, minio_key: str, filename: str) -> None:
    from celery_app import app as _app  # noqa: PLC0415

    _app.send_task(
        "ingest.process_artifact",
        args=[job_id, case_id, minio_key, filename],
        queue="ingest",
    )


# ── plugin ────────────────────────────────────────────────────────────────────


class DDImagePlugin(BasePlugin):
    """
    Parse raw / DD disk images.

    Yields dd_file events (file listing) and dispatches child ingest jobs
    for every extractable file so the existing plugin suite processes them.
    """

    PLUGIN_NAME = "dd_image"
    PLUGIN_VERSION = "1.0.0"
    PLUGIN_PRIORITY = 95  # above plaso (10) but below specific parsers (100)
    DEFAULT_ARTIFACT_TYPE = "dd_file"
    SUPPORTED_EXTENSIONS = [".dd", ".raw"]
    # Raw/dd disk image — no IANA type; de-facto forensic MIME. The magic-byte
    # check still handles extension-less .img files that arrive without a MIME.
    SUPPORTED_MIME_TYPES = ["application/x-raw-disk-image"]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._listed = 0
        self._extracted = 0
        self._carved = 0
        self._skipped = 0
        self._tmpdir: Path | None = None
        self._mc = None  # MinIO client
        self._rc = None  # Redis client

    # ── detection ─────────────────────────────────────────────────────────────

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        ext = file_path.suffix.lower()
        if ext in (".dd", ".raw"):
            return True
        if ext == ".img":
            return _is_disk_image(file_path)
        return False

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def setup(self) -> None:
        if not _TSK_OK:
            raise PluginFatalError("pytsk3 is not installed — rebuild the processor image.")
        if not _MINIO_SDK_OK:
            raise PluginFatalError("minio SDK not available")
        self._tmpdir = Path(tempfile.mkdtemp(prefix="fo_dd_"))
        self._mc = _minio()
        self._rc = _redis()

    def teardown(self) -> None:
        if self._tmpdir and self._tmpdir.exists():
            shutil.rmtree(self._tmpdir, ignore_errors=True)
        try:
            if self._rc:
                self._rc.close()
        except Exception:
            pass

    def get_stats(self) -> dict[str, Any]:
        return {
            "files_listed": self._listed,
            "files_extracted": self._extracted,
            "files_carved": self._carved,
            "files_skipped": self._skipped,
        }

    # ── main parse ────────────────────────────────────────────────────────────

    def parse(self) -> Generator[dict[str, Any], None, None]:
        img_path = str(self.ctx.source_file_path)
        img = pytsk3.Img_Info(img_path)

        # Try partition table first; fall back to treating image as raw filesystem
        opened_any = False
        try:
            volume = pytsk3.Volume_Info(img)
            blk = volume.info.block_size
            for part in volume:
                if not (part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC):
                    continue
                offset = part.addr * blk
                label = f"P{part.addr}"
                fs = None
                try:
                    fs = pytsk3.FS_Info(img, offset=offset)
                except Exception as exc:
                    if _is_bitlocker_volume(img_path, offset):
                        bk = ""
                        if self._rc:
                            bk = (
                                self._rc.hget(f"case:{self.ctx.case_id}", "bitlocker_recovery_key")
                                or ""
                            ).strip()
                        if bk:
                            try:
                                self.log.info(
                                    "BitLocker partition %s at offset %d — decrypting…",
                                    label,
                                    offset,
                                )
                                dec_path = _decrypt_bitlocker(img_path, offset, bk, self._tmpdir)
                                dec_img = pytsk3.Img_Info(str(dec_path))
                                fs = pytsk3.FS_Info(dec_img)
                            except Exception as dec_exc:
                                self.log.warning(
                                    "BitLocker decryption failed for %s: %s", label, dec_exc
                                )
                        else:
                            self.log.warning(
                                "BitLocker partition %s detected — set recovery key in case settings to extract",
                                label,
                            )
                    else:
                        self.log.debug("Partition %s: unrecognised FS (%s)", label, exc)
                if fs is None:
                    continue
                opened_any = True
                yield from self._walk(fs, label)
        except Exception:
            pass  # no partition table — fall through

        if not opened_any:
            try:
                fs = pytsk3.FS_Info(img)
                yield from self._walk(fs, "P0")
            except Exception as exc:
                raise PluginFatalError(f"Cannot open disk image as filesystem: {exc}") from exc

        # PhotoRec carving (unallocated space)
        yield from self._carve(img_path)

    # ── filesystem walker ─────────────────────────────────────────────────────

    def _walk(
        self,
        fs: pytsk3.FS_Info,
        part_label: str,
        path: str = "/",
    ) -> Generator[dict[str, Any], None, None]:
        try:
            directory = fs.open_dir(path=path)
        except Exception:
            return

        for entry in directory:
            try:
                raw_name = entry.info.name.name
                name = (
                    raw_name.decode("utf-8", errors="replace")
                    if isinstance(raw_name, bytes)
                    else str(raw_name)
                )
            except Exception:
                continue

            if name in _SKIP_NAMES:
                continue

            meta = entry.info.meta
            if meta is None:
                continue

            is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_DIR
            is_deleted = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
            filepath = f"{path.rstrip('/')}/{name}"

            if is_dir:
                yield from self._walk(fs, part_label, path=filepath)
                continue

            size = meta.size or 0
            mtime = _iso(getattr(meta, "mtime", None))
            atime = _iso(getattr(meta, "atime", None))
            crtime = _iso(getattr(meta, "crtime", None))

            # Extract allocted files within size limit
            child_job_id = None
            if not is_deleted and 0 < size <= _MAX_BYTES:
                child_job_id = self._extract(fs, meta, name, part_label, filepath)

            self._listed += 1
            yield {
                "artifact_type": "dd_file",
                "timestamp": mtime or crtime or atime or None,
                "timestamp_desc": "Modified",
                "message": (
                    f"[{part_label}] {filepath}  ({size:,} bytes)"
                    + (" [DELETED]" if is_deleted else "")
                    + (
                        ""
                        if child_job_id
                        else "  [not extracted]"
                        if not is_deleted and size > 0
                        else ""
                    )
                ),
                "dd": {
                    "partition": part_label,
                    "path": filepath,
                    "filename": name,
                    "size_bytes": size,
                    "inode": meta.addr,
                    "is_deleted": is_deleted,
                    "modified": mtime,
                    "accessed": atime,
                    "created": crtime,
                    "child_job_id": child_job_id,
                    "source_image": self.ctx.source_file_path.name,
                },
            }

    # ── single-file extraction ────────────────────────────────────────────────

    def _extract(
        self,
        fs: pytsk3.FS_Info,
        meta: Any,
        filename: str,
        part_label: str,
        filepath: str,
    ) -> str | None:
        """
        Stream one file from the disk image → temp file → MinIO.
        Dispatches a child ingest job.  Returns child job_id or None on error.
        """
        size = meta.size
        try:
            f_obj = fs.open_meta(inode=meta.addr)
        except Exception as exc:
            self.log.debug("open_meta failed inode=%s %s: %s", meta.addr, filename, exc)
            self._skipped += 1
            return None

        # Stream to temp file
        safe_name = filename.replace("/", "_").replace("\\", "_")
        tmp_path = self._tmpdir / f"{meta.addr}_{safe_name}"
        try:
            with open(tmp_path, "wb") as out:
                offset = 0
                while offset < size:
                    to_read = min(_CHUNK, size - offset)
                    data = f_obj.read_random(offset, to_read)
                    if not data:
                        break
                    out.write(data)
                    offset += len(data)
        except Exception as exc:
            self.log.warning("Read failed %s: %s", filepath, exc)
            self._skipped += 1
            tmp_path.unlink(missing_ok=True)
            return None

        # Upload to MinIO
        child_job_id = uuid.uuid4().hex
        minio_key = (
            f"cases/{self.ctx.case_id}/{self.ctx.job_id}_dd/{part_label}/{child_job_id}/{safe_name}"
        )
        try:
            self._mc.fput_object(_BUCKET, minio_key, str(tmp_path))
        except Exception as exc:
            self.log.warning("MinIO upload failed %s: %s", filepath, exc)
            self._skipped += 1
            return None
        finally:
            tmp_path.unlink(missing_ok=True)

        _register_child_job(
            self._rc,
            child_job_id,
            self.ctx.case_id,
            safe_name,
            minio_key,
            self.ctx.job_id,
        )
        _dispatch(child_job_id, self.ctx.case_id, minio_key, safe_name)
        self._extracted += 1
        return child_job_id

    # ── photorec carving ──────────────────────────────────────────────────────

    def _carve(self, img_path: str) -> Generator[dict[str, Any], None, None]:
        photorec_bin = shutil.which("photorec")
        if not photorec_bin:
            self.log.info("photorec not found — skipping file carving")
            return

        carved_dir = self._tmpdir / "carved"
        carved_dir.mkdir(parents=True, exist_ok=True)
        self.log.info("Running PhotoRec on %s …", img_path)

        try:
            subprocess.run(
                [
                    photorec_bin,
                    "/log",
                    "/d",
                    str(carved_dir),
                    "/cmd",
                    img_path,
                    "search",
                ],
                capture_output=True,
                timeout=7200,  # 2 h — large images can take a while
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.log.warning("PhotoRec timed out — using partial results")
        except Exception as exc:
            self.log.warning("PhotoRec failed: %s", exc)
            return

        for carved_file in sorted(carved_dir.rglob("*")):
            if not carved_file.is_file():
                continue
            size = carved_file.stat().st_size
            if size == 0 or size > _MAX_BYTES:
                continue

            fname = carved_file.name
            child_job_id = uuid.uuid4().hex
            minio_key = (
                f"cases/{self.ctx.case_id}/{self.ctx.job_id}_dd/carved/{child_job_id}/{fname}"
            )
            try:
                self._mc.fput_object(_BUCKET, minio_key, str(carved_file))
            except Exception as exc:
                self.log.warning("Upload carved %s: %s", fname, exc)
                continue

            _register_child_job(
                self._rc,
                child_job_id,
                self.ctx.case_id,
                fname,
                minio_key,
                self.ctx.job_id,
            )
            _dispatch(child_job_id, self.ctx.case_id, minio_key, fname)
            self._carved += 1

            yield {
                "artifact_type": "dd_carved",
                "timestamp": None,
                "timestamp_desc": "Carved",
                "message": f"[carved] {fname}  ({size:,} bytes)",
                "dd": {
                    "partition": "carved",
                    "path": f"/carved/{fname}",
                    "filename": fname,
                    "size_bytes": size,
                    "inode": None,
                    "is_deleted": True,
                    "modified": "",
                    "accessed": "",
                    "created": "",
                    "child_job_id": child_job_id,
                    "source_image": Path(img_path).name,
                },
            }
