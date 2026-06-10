"""
Disk Image plugin — walks the filesystem of a raw or EWF disk image and indexes
every file/directory entry as a forensic event with artifact_type=diskimage.

Supported formats:
  Raw (.dd .img .raw .001)  — requires pytsk3
  EWF (.e01 .ex01)          — requires pytsk3 + pyewf

Each yielded event contains:
  diskimage.name, .path, .parent  — filesystem location
  diskimage.size, .inode          — file metadata
  diskimage.is_dir                — True for directories
  diskimage.mtime/atime/ctime     — ISO8601 timestamps when available

The directory-browser endpoint in case_files.py queries these events by
diskimage.parent to render a live file tree without re-mounting the image.

Dependencies (add to processor/requirements.txt):
  pytsk3>=20211111
  pyewf>=20201230   (EWF/E01 only)
"""

from __future__ import annotations

import logging
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

logger = logging.getLogger(__name__)

# ── Optional imports ──────────────────────────────────────────────────────────

try:
    import pytsk3

    _HAS_PYTSK3 = True
except ImportError:
    _HAS_PYTSK3 = False
    logger.warning("pytsk3 not installed — disk image plugin unavailable. pip install pytsk3")

try:
    import pyewf

    _HAS_PYEWF = True
except ImportError:
    _HAS_PYEWF = False

_EWF_EXTS = {".e01", ".ex01", ".l01", ".lx01"}


# ── pyewf adapter ─────────────────────────────────────────────────────────────

if _HAS_PYTSK3:

    class _EwfImgInfo(pytsk3.Img_Info):
        """Wraps a pyewf handle so pytsk3 can read EWF images."""

        def __init__(self, ewf_handle):
            self._ewf_handle = ewf_handle
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset, length):
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(length)

        def get_size(self):
            return self._ewf_handle.get_media_size()
else:
    _EwfImgInfo = None  # type: ignore[assignment]


# ── Helpers ───────────────────────────────────────────────────────────────────


def _ts(unix_ts) -> str:
    if not unix_ts:
        return ""
    try:
        return datetime.fromtimestamp(int(unix_ts), tz=UTC).isoformat()
    except (OSError, OverflowError, ValueError):
        return ""


# ── Plugin ────────────────────────────────────────────────────────────────────


class DiskImagePlugin(BasePlugin):
    PLUGIN_NAME = "diskimage"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "diskimage"
    SUPPORTED_EXTENSIONS = [
        ".dd",
        ".img",
        ".raw",
        ".001",
        ".e01",
        ".ex01",
        ".l01",
        ".lx01",
    ]
    # Raw disk images and EnCase EWF (E01) containers — no IANA types.
    SUPPORTED_MIME_TYPES = [
        "application/x-raw-disk-image",
        "application/x-ewf",
    ]
    PLUGIN_PRIORITY = 60

    def parse(self) -> Generator[dict[str, Any], None, None]:
        if not _HAS_PYTSK3:
            raise PluginFatalError(
                "pytsk3 not installed. Add pytsk3 to processor/requirements.txt and rebuild."
            )

        path = str(self.ctx.source_file_path)
        ext = Path(path).suffix.lower()

        # Open image
        try:
            if ext in _EWF_EXTS:
                if not _HAS_PYEWF:
                    raise PluginFatalError("pyewf required for E01 images. pip install pyewf")
                filenames = pyewf.glob(path)
                ewf_handle = pyewf.handle()
                ewf_handle.open(filenames)
                img = _EwfImgInfo(ewf_handle)
            else:
                img = pytsk3.Img_Info(path)
        except PluginFatalError:
            raise
        except Exception as exc:
            raise PluginFatalError(f"Cannot open disk image: {exc}")

        yield from self._walk_image(img)

    def _walk_image(self, img) -> Generator[dict, None, None]:
        """Try a volume system first, fall back to direct filesystem open."""
        try:
            vol = pytsk3.Volume_Info(img)
            for part in vol:
                if part.flags != pytsk3.TSK_VS_PART_FLAG_ALLOC:
                    continue
                try:
                    fs = pytsk3.FS_Info(img, offset=part.start * vol.info.block_size)
                    label = f"part{part.addr}"
                    self.log.info("Partition %s: offset=%d", label, part.start)
                    yield from self._walk_fs(fs, label=label)
                except Exception as exc:
                    self.log.debug("Skipping partition %d: %s", part.addr, exc)
        except Exception:
            # Not a partitioned image — try as a raw filesystem
            try:
                fs = pytsk3.FS_Info(img)
                yield from self._walk_fs(fs, label="")
            except Exception as exc:
                raise PluginFatalError(f"Cannot open filesystem: {exc}")

    def _walk_fs(self, fs, label: str = "") -> Generator[dict, None, None]:
        """Iterative DFS walk; one event per file-system entry."""
        stack = ["/"]
        seen_inodes: set[int] = set()

        while stack:
            dirpath = stack.pop()
            try:
                directory = fs.open_dir(path=dirpath)
            except Exception as exc:
                self.log.debug("Cannot open '%s': %s", dirpath, exc)
                continue

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

                if name in (".", ".."):
                    continue

                meta = entry.info.meta
                if meta is None:
                    continue

                inode = meta.addr
                if inode in seen_inodes:
                    continue  # Hard-link duplicate
                seen_inodes.add(inode)

                is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_DIR

                parent = dirpath.rstrip("/") + "/"
                if parent == "//":
                    parent = "/"
                full_path = (parent.rstrip("/") + "/" + name) if parent != "/" else ("/" + name)

                mtime = _ts(meta.mtime)
                atime = _ts(meta.atime)
                ctime = _ts(getattr(meta, "crtime", None) or meta.ctime)
                size = 0 if is_dir else meta.size
                ts = mtime or atime or ctime

                msg = f"{'[DIR] ' if is_dir else ''}{full_path}"
                if not is_dir and size:
                    msg += f" ({size:,} bytes)"

                yield {
                    "timestamp": ts,
                    "timestamp_desc": "Modified",
                    "message": msg,
                    "artifact_type": "diskimage",
                    "diskimage": {
                        "name": name,
                        "path": full_path,
                        "parent": parent,
                        "size": size,
                        "inode": inode,
                        "is_dir": is_dir,
                        "mtime": mtime,
                        "atime": atime,
                        "ctime": ctime,
                        "label": label,
                    },
                }

                if is_dir and inode not in (0, 1, 2):
                    stack.append(full_path)
