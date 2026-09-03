"""Integrity gate for plugin/ingester modules before they are imported.

Loading a plugin means executing it: ``spec.loader.exec_module()`` runs whatever
Python is in the file, with the full privileges of the API or worker process.
The loaders find candidates by filename glob (``*_plugin.py`` /
``*_ingester.py``) on a shared, writable volume, so any path that can drop a
file into that volume is an arbitrary-code-execution path into both containers.

This module adds two checks that run before the import:

1. **Unsafe file mode** — a plugin that is group- or world-writable is
   rejected outright. On a shared volume that is the difference between "the
   operator installed this" and "anything on the box could have rewritten it".
   This is always enforced.

2. **sha256 allowlist** — when a trust manifest is configured, a plugin is
   imported only if its digest is listed in it. The manifest lives OUTSIDE the
   plugins volume (that is the point: code on the volume must not be able to
   authorise itself), and is enforced fail-closed — an unlisted or modified
   file is skipped, not loaded.

The manifest is opt-in because the Studio UI legitimately writes new ingesters
into the volume at runtime; a deployment that does not use that feature should
set ``PLUGIN_TRUST_MANIFEST`` and get a hard allowlist. Either way every load
is logged with its digest, so what executed is always attributable.

Manifest format (JSON)::

    {
      "plugins": {
        "evtx/evtx_plugin.py": "9f86d081884c7d659a2feaa0c55ad015a...",
        "wer/wer_plugin.py":   "2c26b46b68ffc68ff99b453c1d304134..."
      }
    }

Keys are paths relative to the scanned root, POSIX separators.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
from pathlib import Path

logger = logging.getLogger(__name__)

__all__ = ["PluginTrustStore", "sha256_file"]

_MANIFEST_ENV = "PLUGIN_TRUST_MANIFEST"
# Group/other write bits. A plugin file carrying either of these can be
# rewritten by something other than the account that installed it.
_UNSAFE_MODE_BITS = stat.S_IWGRP | stat.S_IWOTH


def sha256_file(path: Path) -> str:
    """Hex sha256 of ``path``, read in chunks (plugins can be large)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class PluginTrustStore:
    """Decides whether a candidate plugin file may be imported."""

    def __init__(self, manifest_path: str | os.PathLike[str] | None = None) -> None:
        raw = manifest_path if manifest_path is not None else os.getenv(_MANIFEST_ENV, "")
        self.manifest_path = Path(raw) if raw else None
        self._digests: dict[str, str] = {}
        self.enforcing = False
        self._load_manifest()

    def _load_manifest(self) -> None:
        if self.manifest_path is None:
            logger.warning(
                "Plugin integrity manifest not configured (%s unset) — plugin "
                "files will be imported on filename match alone. Any write "
                "access to the plugins volume is code execution in this "
                "process. Set %s to a manifest outside the volume to enforce "
                "a sha256 allowlist.",
                _MANIFEST_ENV,
                _MANIFEST_ENV,
            )
            return
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            entries = data.get("plugins", {})
            if not isinstance(entries, dict):
                raise ValueError("'plugins' must be an object of path → sha256")
            self._digests = {
                str(k).replace("\\", "/"): str(v).strip().lower() for k, v in entries.items()
            }
        except FileNotFoundError:
            # Configured but absent is a deployment error, not a reason to
            # silently fall back to loading everything.
            raise RuntimeError(
                f"{_MANIFEST_ENV} points at {self.manifest_path}, which does not "
                f"exist. Refusing to load plugins without the integrity manifest "
                f"it names — unset {_MANIFEST_ENV} to run unenforced."
            ) from None
        except Exception as exc:
            raise RuntimeError(
                f"Plugin integrity manifest {self.manifest_path} is unreadable "
                f"or malformed ({exc}). Refusing to load plugins."
            ) from exc

        self.enforcing = True
        logger.info(
            "Plugin integrity enforcement ON — %d allowlisted digest(s) from %s",
            len(self._digests),
            self.manifest_path,
        )

    def allows(self, path: Path, root: Path) -> bool:
        """True if ``path`` may be imported. Logs the reason when it may not."""
        try:
            mode = path.stat().st_mode
        except OSError as exc:
            logger.error("Skipping plugin %s — cannot stat it: %s", path, exc)
            return False

        if mode & _UNSAFE_MODE_BITS:
            logger.error(
                "Skipping plugin %s — file mode %o is group/world-writable, so "
                "its contents are not trustworthy. Fix with: chmod go-w %s",
                path,
                stat.S_IMODE(mode),
                path,
            )
            return False

        try:
            digest = sha256_file(path)
        except OSError as exc:
            logger.error("Skipping plugin %s — cannot hash it: %s", path, exc)
            return False

        try:
            rel = path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            # Outside the scanned root: the loader should never hand us this.
            logger.error("Skipping plugin %s — outside the plugin root %s", path, root)
            return False

        if not self.enforcing:
            logger.info("Loading plugin %s (sha256=%s, unenforced)", rel, digest)
            return True

        expected = self._digests.get(rel)
        if expected is None:
            logger.error(
                "Skipping plugin %s — not listed in the integrity manifest %s "
                "(sha256=%s). Add it deliberately if it is meant to run.",
                rel,
                self.manifest_path,
                digest,
            )
            return False
        if expected != digest:
            logger.error(
                "Skipping plugin %s — sha256 mismatch. Manifest expects %s, "
                "file is %s. The file has been modified since it was approved.",
                rel,
                expected,
                digest,
            )
            return False

        logger.info("Loading plugin %s (sha256=%s, allowlisted)", rel, digest)
        return True
