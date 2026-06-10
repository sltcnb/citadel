#!/usr/bin/env python3
"""
Talon — pluggable ArtifactCollector interface
==============================================
A small, stdlib-only abstraction layer that turns the monolithic ``collect.py``
collectors into pluggable units with an explicit lifecycle:

    start()      → prepare staging, record session metadata
    collect()    → gather the declared artifact categories into the bundle
    finalize()   → seal the bundle (manifest.json + bundle.sha256) and return it

Each implementation also *declares* which artifact categories it can produce via
:meth:`categories`, so an orchestrator (Sluice / the gRPC agent) can negotiate a
collection profile without importing the collector internals.

The produced bundle conforms to the shared contract
``contracts/bundle_manifest.schema.json`` (Bundle layout:
``bundle/ { manifest.json | events.jsonl | blobs/<sha256> | bundle.sha256 }``).

This module is intentionally decoupled from ``collect.py``: the existing CLI keeps
working unchanged, while :class:`CollectorAdapter` wraps any legacy
``collect.Collector`` subclass and exposes it through this interface, refactoring
one collection path onto the plugin contract without rewriting the 4k-line file.
"""

from __future__ import annotations

import abc
import datetime
import hashlib
import json
import platform
import socket
from dataclasses import dataclass, field
from pathlib import Path

CHUNK_READ = 1024 * 1024  # 1 MiB read window for hashing

# ── OS classification matching the bundle_manifest contract enum ──────────────
_OS_ENUM = {"windows": "windows", "linux": "linux", "darwin": "macos"}


def host_os() -> str:
    """Return the manifest-conformant OS string for the running host."""
    return _OS_ENUM.get(platform.system().lower(), "unknown")


def sha256_file(path: Path) -> str:
    """Streaming SHA-256 of a file (hex)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK_READ), b""):
            h.update(block)
    return h.hexdigest()


@dataclass
class ArtifactRef:
    """One collected artifact, as it appears in the manifest ``artifacts[]``."""

    name: str  # path inside the bundle (e.g. blobs/<sha256> or arcname)
    sha256: str
    size: int
    category: str

    def to_manifest(self) -> dict:
        return {
            "name": self.name,
            "sha256": self.sha256,
            "size": self.size,
            "category": self.category,
        }


@dataclass
class CollectionResult:
    """Outcome of a full start/collect/finalize cycle."""

    session_id: str
    hostname: str
    os: str
    started_at: str
    finished_at: str | None = None
    artifacts: list[ArtifactRef] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(a.size for a in self.artifacts)

    def to_manifest(self) -> dict:
        """Render the contract-conformant manifest.json payload."""
        manifest = {
            "session_id": self.session_id,
            "hostname": self.hostname,
            "os": self.os,
            "started_at": self.started_at,
            "artifacts": [a.to_manifest() for a in self.artifacts],
            "artifact_count": len(self.artifacts),
            "total_bytes": self.total_bytes,
            "errors": list(self.errors),
        }
        if self.finished_at:
            manifest["finished_at"] = self.finished_at
        return manifest


class ArtifactCollector(abc.ABC):
    """
    Abstract base for a pluggable artifact collector.

    Lifecycle contract (the orchestrator calls these in order)::

        c = SomeCollector(...)
        c.start()
        c.collect()                # populates the bundle / result
        result = c.finalize()      # seals manifest + bundle.sha256

    Subclasses must implement :meth:`categories`, :meth:`start`, :meth:`collect`
    and :meth:`finalize`.
    """

    def __init__(
        self, session_id: str, *, hostname: str | None = None, os_name: str | None = None
    ) -> None:
        self.session_id = session_id
        self.hostname = hostname or socket.gethostname()
        self.os = os_name or host_os()
        self.result = CollectionResult(
            session_id=self.session_id,
            hostname=self.hostname,
            os=self.os,
            started_at=_now_iso(),
        )

    # ── Declarative ───────────────────────────────────────────────────────────
    @abc.abstractmethod
    def categories(self) -> set[str]:
        """Artifact categories this collector is configured to produce."""

    @classmethod
    def supported_categories(cls) -> set[str]:
        """All categories this collector *class* is capable of producing.

        Defaults to the empty set; concrete plugins should override.
        """
        return set()

    # ── Lifecycle ──────────────────────────────────────────────────────────────
    @abc.abstractmethod
    def start(self) -> None:
        """Prepare for collection (staging dirs, privileges, mounts)."""

    @abc.abstractmethod
    def collect(self) -> None:
        """Run collection for the declared categories."""

    @abc.abstractmethod
    def finalize(self) -> CollectionResult:
        """Seal the bundle and return the :class:`CollectionResult`."""


def _now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────────────────────────────────────────────────────────
# Adapter — wrap a legacy collect.Collector behind the plugin interface
# ─────────────────────────────────────────────────────────────────────────────
class CollectorAdapter(ArtifactCollector):
    """
    Bridges the existing ``collect.Collector`` subclasses (WindowsCollector,
    LinuxCollector, MacOSCollector, ExternalDiskCollector) onto the pluggable
    :class:`ArtifactCollector` interface — **without changing collect.py's CLI**.

    The legacy collector keeps its imperative ``collect_all`` / ``package`` /
    ``cleanup`` flow; this adapter maps it to start/collect/finalize and emits a
    contract-conformant manifest derived from the collector's staged ``_items``.
    """

    def __init__(
        self, legacy, session_id: str, *, hostname: str | None = None, os_name: str | None = None
    ) -> None:
        super().__init__(session_id, hostname=hostname, os_name=os_name)
        self._legacy = legacy
        # Map each requested category key to a human label where available.
        try:
            from collect import ARTIFACT_LABELS  # type: ignore

            self._labels = ARTIFACT_LABELS
        except Exception:
            self._labels = {}

    def categories(self) -> set[str]:
        return set(getattr(self._legacy, "collect", set()))

    def start(self) -> None:
        # Legacy collectors prepare staging in __init__; nothing extra needed.
        self.result.started_at = _now_iso()

    def collect(self) -> None:
        self._legacy.collect_all()

    def finalize(self) -> CollectionResult:
        """
        Build the manifest from the collector's staged items. Each ``_items``
        entry is ``(arcname, src_path)``; we hash and size every staged file and
        attribute it to a category (best-effort from the arcname's top segment).
        """
        items = getattr(self._legacy, "_items", [])
        for arcname, src in items:
            src = Path(src)
            try:
                size = src.stat().st_size
                digest = sha256_file(src)
            except OSError as exc:
                self.result.errors.append(f"hash failed {arcname}: {exc}")
                continue
            category = _category_for(arcname)
            self.result.artifacts.append(
                ArtifactRef(name=arcname, sha256=digest, size=size, category=category)
            )

        for err in getattr(self._legacy, "_errors", []):
            self.result.errors.append(str(err))

        self.result.finished_at = _now_iso()
        return self.result

    def write_bundle_manifest(self, dest: Path) -> Path:
        """Write the bundle manifest and return its path.

        ``dest`` may be either a directory (the manifest is written as
        ``dest/manifest.json``) or an explicit file path (honored verbatim,
        so a user-supplied filename is never silently ignored). A path that
        is an existing directory, or has no suffix, is treated as a directory;
        anything else is treated as the target file.
        """
        if dest.is_dir() or not dest.suffix:
            manifest_path = dest / "manifest.json"
        else:
            manifest_path = dest
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(self.result.to_manifest(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return manifest_path


def _category_for(arcname: str) -> str:
    """Best-effort artifact category from a bundle arcname."""
    head = arcname.replace("\\", "/").split("/", 1)[0]
    return head or "unknown"
