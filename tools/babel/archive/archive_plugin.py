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

# ── Safety limits against zip-bomb / decompression-bomb attacks ────────────────
# All configurable via env so operators can tune for large-evidence workloads.
#
#   MAX_EXTRACTED_BYTES  — per-archive uncompressed cap (each archive/tempdir).
#   MAX_GLOBAL_BYTES     — shared budget across an archive and every nested
#                          archive re-fed through the pipeline, so N levels of
#                          nesting can't multiplicatively amplify extraction.
#   MAX_FILES            — max member count processed per archive.
#   MAX_DEPTH            — max nested-archive recursion depth (0 = top level).
MAX_EXTRACTED_BYTES = int(os.getenv("ARCHIVE_MAX_EXTRACTED_BYTES", str(2 * 1024**3)))  # 2 GiB
MAX_GLOBAL_BYTES = int(os.getenv("ARCHIVE_MAX_GLOBAL_BYTES", str(10 * 1024**3)))  # 10 GiB
MAX_FILES = int(os.getenv("ARCHIVE_MAX_FILES", "10000"))
MAX_DEPTH = int(os.getenv("ARCHIVE_MAX_DEPTH", "3"))

_COPY_CHUNK = 1024 * 1024  # 1 MiB

# Config keys used to thread recursion depth + shared byte budget through the
# plugin pipeline when nested archives are re-fed.
_CFG_DEPTH = "_archive_depth"
_CFG_BUDGET = "_archive_budget"


class _ExtractionLimit(Exception):
    """Raised internally when a per-archive or global byte cap is crossed."""


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

        # Recursion depth + shared byte budget are threaded through PluginContext
        # config so nested archives re-fed via _process_dir share one budget.
        cfg = getattr(self.ctx, "config", None) or {}
        self._depth = int(cfg.get(_CFG_DEPTH, 0))
        # Budget is a 1-element mutable list so nested plugins mutate the same one.
        budget = cfg.get(_CFG_BUDGET)
        if not isinstance(budget, list) or not budget:
            budget = [MAX_GLOBAL_BYTES]
        self._budget = budget
        self._archive_bytes = 0

        if self._depth > MAX_DEPTH:
            self.log.warning(
                "Max archive recursion depth (%d) exceeded — not extracting %s",
                MAX_DEPTH,
                fp.name,
            )
            return

        extract_dir = Path(tempfile.mkdtemp(prefix="fo_arc_"))
        try:
            extracted_ok = self._extract(fp, extract_dir)
            if not extracted_ok:
                raise PluginFatalError(f"Unsupported or corrupted archive: {fp.name}")
            yield from self._process_dir(extract_dir)
        finally:
            shutil.rmtree(extract_dir, ignore_errors=True)

    # ── Bounded copy (per-archive cap + shared global budget) ──────────────────

    def _bounded_extract_copy(self, src, dst) -> None:
        """Copy src→dst in chunks, aborting the moment the running total crosses
        either the per-archive cap or the shared global budget. This enforces the
        limit DURING copy so a member lying about its declared size can't inflate
        past the cap."""
        while True:
            chunk = src.read(_COPY_CHUNK)
            if not chunk:
                break
            n = len(chunk)
            self._archive_bytes += n
            self._budget[0] -= n
            if self._archive_bytes > MAX_EXTRACTED_BYTES:
                raise _ExtractionLimit(
                    f"per-archive uncompressed cap ({MAX_EXTRACTED_BYTES} bytes) exceeded"
                )
            if self._budget[0] < 0:
                raise _ExtractionLimit(
                    f"global extraction budget ({MAX_GLOBAL_BYTES} bytes) exhausted"
                )
            dst.write(chunk)

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

    def _safe_target(self, dest: Path, name: str) -> Path | None:
        """Resolve *name* under *dest*, rejecting zip-slip / path traversal.

        normpath alone is not enough: normpath('../../etc/x') keeps the '..',
        so verify the resolved target stays inside dest before writing.
        """
        safe_name = os.path.normpath(name).lstrip(os.sep)
        out = dest / safe_name
        try:
            out.resolve().relative_to(dest.resolve())
        except (ValueError, OSError):
            return None
        return out

    def _extract_zip(self, archive_path: Path, dest: Path) -> bool:
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    # Cheap declared-size reject before we bother reading bytes.
                    if (info.file_size or 0) > MAX_EXTRACTED_BYTES:
                        self.log.warning(
                            "ZIP entry %r declares %d bytes (> cap) — skipped",
                            info.filename,
                            info.file_size,
                        )
                        continue
                    out = self._safe_target(dest, info.filename)
                    if out is None:
                        self.log.warning(
                            "Rejected unsafe ZIP entry (path traversal): %r",
                            info.filename,
                        )
                        continue
                    out.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        with zf.open(info) as src, open(out, "wb") as dst:
                            self._bounded_extract_copy(src, dst)
                    except _ExtractionLimit as exc:
                        out.unlink(missing_ok=True)
                        self.log.warning("ZIP extraction stopped: %s", exc)
                        break
            return True
        except zipfile.BadZipFile as exc:
            raise PluginFatalError(f"Bad ZIP file: {exc}")

    def _extract_tar(self, archive_path: Path, dest: Path) -> bool:
        try:
            with tarfile.open(archive_path) as tf:
                for m in tf:
                    if not m.isfile():
                        continue
                    # Cheap declared-size reject before reading member bytes.
                    if (m.size or 0) > MAX_EXTRACTED_BYTES:
                        self.log.warning(
                            "TAR member %r declares %d bytes (> cap) — skipped",
                            m.name,
                            m.size,
                        )
                        continue
                    out = self._safe_target(dest, m.name)
                    if out is None:
                        self.log.warning(
                            "Rejected unsafe TAR member (path traversal): %r", m.name
                        )
                        continue
                    src = tf.extractfile(m)
                    if src is None:
                        continue
                    out.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        with src, open(out, "wb") as dst:
                            self._bounded_extract_copy(src, dst)
                    except _ExtractionLimit as exc:
                        out.unlink(missing_ok=True)
                        self.log.warning("TAR extraction stopped: %s", exc)
                        break
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

                # Thread recursion depth + shared byte budget so a nested archive
                # re-fed through the pipeline can't amplify extraction unbounded.
                sub_config = dict(getattr(self.ctx, "config", None) or {})
                sub_config[_CFG_DEPTH] = self._depth + 1
                sub_config[_CFG_BUDGET] = self._budget

                sub_ctx = PluginContext(
                    case_id=self.ctx.case_id,
                    job_id=self.ctx.job_id,
                    source_file_path=extracted_file,
                    source_minio_url=self.ctx.source_minio_url,
                    config=sub_config,
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
