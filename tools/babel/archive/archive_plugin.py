"""
Archive plugin — recursively extracts ZIP and TAR-family archives and processes
each contained file through the appropriate plugin.

Supports:
  .zip, .tar, .tgz, .tar.gz, .tar.bz2, .tar.xz

Each file extracted from the archive is passed through the full plugin-selection
pipeline (the same PluginLoader used by the ingest task), so nested forensic
artifacts (EVTX inside a ZIP, registry hives inside a TGZ, etc.) are parsed by
their dedicated plugin rather than the strings fallback.

Priority 80 — tried before generic fallbacks (strings=1, plaso=10) but after
specific high-priority forensic parsers (evtx, mft, etc. at 100+).
"""

from __future__ import annotations

import logging
import os
import shutil
import tarfile
import tempfile
import zipfile
from collections.abc import Generator
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

logger = logging.getLogger(__name__)

# Safety limits against zip-bomb attacks
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB total
MAX_FILES = 10_000

# Junk files to skip (macOS metadata, Windows thumbs, etc.)
_SKIP_NAMES = {".ds_store", "thumbs.db", "desktop.ini"}
_SKIP_DIRS = {"__macosx"}


def _is_junk(path: Path) -> bool:
    return path.name.lower() in _SKIP_NAMES or any(p.lower() in _SKIP_DIRS for p in path.parts)


class ArchivePlugin(BasePlugin):
    PLUGIN_NAME = "archive"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "generic"
    PLUGIN_PRIORITY = 80  # before strings(1) and plaso(10), after specific parsers

    # Extensions handled via can_handle below; listed here for /plugins UI only
    SUPPORTED_EXTENSIONS = [".zip", ".tar", ".tgz"]
    SUPPORTED_MIME_TYPES = [
        "application/zip",
        "application/x-zip-compressed",
        "application/x-tar",
        "application/gzip",
        "application/x-gzip",
        "application/x-bzip2",
        "application/x-xz",
    ]

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        name = file_path.name.lower()
        # Multi-extension variants (.tar.gz, .tar.bz2, .tar.xz) must be caught
        # by name because suffix only returns the last extension.
        if any(name.endswith(s) for s in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz")):
            return True
        if file_path.suffix.lower() in (".zip", ".tar"):
            return True
        # MIME fallback for files whose extension was stripped or renamed
        if mime_type in cls.SUPPORTED_MIME_TYPES:
            # Guard: don't claim .gz that is a single compressed file (e.g. file.evtx.gz)
            # Only claim gzip MIME if we can actually open it as a tar archive.
            if mime_type in ("application/gzip", "application/x-gzip"):
                return tarfile.is_tarfile(str(file_path))
            return True
        return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        fp = self.ctx.source_file_path
        extract_dir = Path(tempfile.mkdtemp(prefix="fo_arc_"))
        try:
            extracted_ok = self._extract(fp, extract_dir)
            if not extracted_ok:
                raise PluginFatalError(f"Unsupported or corrupted archive: {fp.name}")
            yield from self._process_dir(extract_dir)
        finally:
            shutil.rmtree(extract_dir, ignore_errors=True)

    # ── Extraction ────────────────────────────────────────────────────────────

    def _extract(self, archive_path: Path, dest: Path) -> bool:
        """Extract archive to dest. Returns True on success."""
        name = archive_path.name.lower()

        if name.endswith(".zip"):
            return self._extract_zip(archive_path, dest)

        # TAR family (.tar, .tgz, .tar.gz, .tar.bz2, .tar.xz)
        try:
            if tarfile.is_tarfile(str(archive_path)):
                return self._extract_tar(archive_path, dest)
        except Exception:
            pass

        return False

    def _extract_zip(self, archive_path: Path, dest: Path) -> bool:
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                total_bytes = 0
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    total_bytes += info.file_size
                    if total_bytes > MAX_EXTRACTED_BYTES:
                        self.log.warning("ZIP extraction stopped: size limit reached")
                        break
                    # Sanitise path to prevent zip-slip. normpath alone is not
                    # enough: normpath('../../etc/x') keeps the '..', so verify
                    # the resolved target stays inside dest before writing.
                    safe_name = os.path.normpath(info.filename).lstrip(os.sep)
                    out = dest / safe_name
                    try:
                        out.resolve().relative_to(dest.resolve())
                    except (ValueError, OSError):
                        self.log.warning(
                            "Rejected unsafe ZIP entry (path traversal): %r",
                            info.filename,
                        )
                        continue
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info) as src, open(out, "wb") as dst:
                        shutil.copyfileobj(src, dst)
            return True
        except zipfile.BadZipFile as exc:
            raise PluginFatalError(f"Bad ZIP file: {exc}")

    def _extract_tar(self, archive_path: Path, dest: Path) -> bool:
        try:
            with tarfile.open(archive_path) as tf:
                total_bytes = 0
                members = []
                for m in tf.getmembers():
                    if m.isfile():
                        total_bytes += m.size
                        if total_bytes > MAX_EXTRACTED_BYTES:
                            self.log.warning("TAR extraction stopped: size limit reached")
                            break
                        members.append(m)
                # Python 3.12+ supports filter='data' for safe extraction
                try:
                    tf.extractall(dest, members=members, filter="data")
                except TypeError:
                    tf.extractall(dest, members=members)  # noqa: S202 (Python < 3.12)
            return True
        except tarfile.TarError as exc:
            raise PluginFatalError(f"TAR extraction failed: {exc}")

    # ── Recursive processing ──────────────────────────────────────────────────

    def _process_dir(self, extract_dir: Path) -> Generator[dict, None, None]:
        """Walk extracted files and process each through the plugin pipeline."""
        # Lazy import to avoid circular dependency at module load time.
        # plugin_loader is in the processor package, not the plugins package.
        try:
            import plugin_loader as _pl

            sub_loader = _pl.PluginLoader(_pl.PLUGINS_DIR, _pl.INGESTER_DIR)
        except (ImportError, AttributeError):
            # Fallback when constants are not exported (older versions)
            from pathlib import Path as _P

            from plugin_loader import PluginLoader

            sub_loader = PluginLoader(_P("/app/babel"), _P("/app/sluice"))

        from utils.file_type import detect_mime

        files_done = 0
        for extracted_file in sorted(extract_dir.rglob("*")):
            if not extracted_file.is_file():
                continue
            if _is_junk(extracted_file):
                continue
            if files_done >= MAX_FILES:
                self.log.warning("Hit MAX_FILES=%d limit in archive, stopping", MAX_FILES)
                break
            files_done += 1

            rel = extracted_file.relative_to(extract_dir)
            try:
                sub_mime = detect_mime(extracted_file)
                sub_class = sub_loader.get_plugin(extracted_file, sub_mime)
                if sub_class is None:
                    self.log.debug("No plugin for %s — skipping", rel)
                    continue

                sub_ctx = PluginContext(
                    case_id=self.ctx.case_id,
                    job_id=self.ctx.job_id,
                    source_file_path=extracted_file,
                    source_minio_url=self.ctx.source_minio_url,
                    logger=self.ctx.logger,
                )
                sub = sub_class(sub_ctx)
                sub.setup()
                try:
                    for event in sub.parse():
                        # Record which file inside the archive produced this event
                        event.setdefault("raw", {})
                        if isinstance(event.get("raw"), dict):
                            event["raw"]["archive_member"] = str(rel)
                            event["raw"]["archive_source"] = self.ctx.source_file_path.name
                        yield event
                finally:
                    sub.teardown()

            except Exception as exc:
                self.log.warning(
                    "Failed to process archive member %s (plugin=%s): %s",
                    rel,
                    sub_class.PLUGIN_NAME if "sub_class" in dir() else "?",
                    exc,
                )
