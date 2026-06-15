"""
Python embed cache + extractor.

Lazily downloads portable Python distributions and yields their files so they
can be embedded into the collector zip. Targets:
  win-x64    — python.org Windows embeddable (~7 MB, stdlib only, no pip)
  linux-x64  — python-build-standalone install_only (~25 MB)
  linux-arm  — python-build-standalone install_only aarch64 (~22 MB)
  macos      — python-build-standalone install_only universal2 (~28 MB)

Archive bytes are cached on disk in EMBEDS_DIR so we only pay the download
cost once per pod lifetime. Re-fetched if the cache file is missing.

Usage:
    from services.python_embeds import iter_embed_members, EMBED_TARGETS

    for name, member in iter_embed_members("win-x64", folder_prefix="python-embed"):
        zip_file.writestr(name, member.read())
"""

from __future__ import annotations

import logging
import os
import tarfile
import urllib.error
import urllib.request
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from services.safe_paths import safe_join

logger = logging.getLogger(__name__)

# Cache directory — persistent volume in production, /tmp fallback.
EMBEDS_DIR = Path(os.environ.get("CITADEL_PYEMBED_CACHE", "/tmp/citadel-pyembeds"))

# Pinned versions so analysts get reproducible bundles. Bump together when
# upgrading; both python-build-standalone tag and CPython version must match.
PBS_TAG = "20241016"  # python-build-standalone release tag
CPY_VERSION = "3.12.7"


@dataclass(frozen=True)
class EmbedSpec:
    """One platform target — URL + archive format + member-prefix-to-strip."""

    label: str
    url: str
    archive: str  # "zip" | "tar.gz"
    strip_prefix: str = ""  # leading dir to remove from each member (e.g. "python/")
    size_mb: float = 0.0  # rough size for UI display


EMBED_TARGETS: dict[str, EmbedSpec] = {
    "win-x64": EmbedSpec(
        label="Windows x64",
        url=f"https://www.python.org/ftp/python/{CPY_VERSION}/python-{CPY_VERSION}-embed-amd64.zip",
        archive="zip",
        size_mb=7.5,
    ),
    "linux-x64": EmbedSpec(
        label="Linux x86_64",
        url=f"https://github.com/astral-sh/python-build-standalone/releases/download/{PBS_TAG}/cpython-{CPY_VERSION}+{PBS_TAG}-x86_64-unknown-linux-gnu-install_only.tar.gz",
        archive="tar.gz",
        strip_prefix="python/",
        size_mb=25.0,
    ),
    "linux-arm64": EmbedSpec(
        label="Linux ARM64",
        url=f"https://github.com/astral-sh/python-build-standalone/releases/download/{PBS_TAG}/cpython-{CPY_VERSION}+{PBS_TAG}-aarch64-unknown-linux-gnu-install_only.tar.gz",
        archive="tar.gz",
        strip_prefix="python/",
        size_mb=22.0,
    ),
    "macos": EmbedSpec(
        label="macOS (universal2)",
        url=f"https://github.com/astral-sh/python-build-standalone/releases/download/{PBS_TAG}/cpython-{CPY_VERSION}+{PBS_TAG}-aarch64-apple-darwin-install_only.tar.gz",
        archive="tar.gz",
        strip_prefix="python/",
        size_mb=28.0,
    ),
}


def _cache_path(target: str) -> Path:
    # target must be one of the pinned allowlist keys — never an arbitrary
    # string — before it is interpolated into a cache filename.
    if target not in EMBED_TARGETS:
        raise ValueError(f"Unknown embed target: {target}")
    spec = EMBED_TARGETS[target]
    suffix = ".zip" if spec.archive == "zip" else ".tar.gz"
    return safe_join(EMBEDS_DIR, f"{target}-{CPY_VERSION}{suffix}")


def _ensure_archive(target: str) -> Path:
    """Download archive if not cached. Return path to local archive file."""
    if target not in EMBED_TARGETS:
        raise ValueError(f"Unknown embed target: {target}")
    EMBEDS_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path(target)
    if path.exists() and path.stat().st_size > 1024:
        return path
    spec = EMBED_TARGETS[target]
    logger.info("Downloading Python embed [%s] from %s …", target, spec.url)
    req = urllib.request.Request(spec.url, headers={"User-Agent": "citadel/1.0"})
    tmp = path.with_suffix(path.suffix + ".part")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as fh:
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
        tmp.rename(path)
        logger.info("Cached %s (%.1f MB)", path, path.stat().st_size / (1024 * 1024))
        return path
    except urllib.error.HTTPError as exc:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"Failed to download {spec.url}: HTTP {exc.code}") from exc
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"Failed to download {spec.url}: {exc}") from exc


def iter_embed_members(
    target: str,
    folder_prefix: str,
) -> Iterator[tuple[str, bytes, bool]]:
    """Yield (zip-path, file-bytes, is-executable) for each member of the embed.

    The yielded `zip-path` is `<folder_prefix>/<stripped-member-name>`. Caller
    writes into their output zip; on extraction the embedded Python sits at
    `<output-dir>/<folder_prefix>/…`.

    `is-executable` is True for files we want to ship with the executable
    permission bit set (so analysts on Linux/macOS get a runnable interpreter
    after unzip).
    """
    if target not in EMBED_TARGETS:
        raise ValueError(f"Unknown embed target: {target}")
    spec = EMBED_TARGETS[target]
    arc_path = _ensure_archive(target)

    if spec.archive == "zip":
        with zipfile.ZipFile(arc_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                if spec.strip_prefix and name.startswith(spec.strip_prefix):
                    name = name[len(spec.strip_prefix) :]
                if not name:
                    continue
                data = zf.read(info)
                # Windows embed: only python.exe / pythonw.exe need exec bit
                exe = name.lower().endswith(".exe")
                yield (f"{folder_prefix}/{name}", data, exe)
        return

    # tar.gz
    with tarfile.open(arc_path, mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            name = member.name
            if spec.strip_prefix and name.startswith(spec.strip_prefix):
                name = name[len(spec.strip_prefix) :]
            if not name:
                continue
            fh = tf.extractfile(member)
            if fh is None:
                continue
            data = fh.read()
            exe = bool(member.mode & 0o111)
            yield (f"{folder_prefix}/{name}", data, exe)


def warm_cache(targets: list[str] | None = None) -> dict[str, str]:
    """Pre-fetch one or more embed archives. Returns {target: status}."""
    out: dict[str, str] = {}
    for t in targets or list(EMBED_TARGETS):
        try:
            p = _ensure_archive(t)
            out[t] = f"ok ({p.stat().st_size // 1024} KB)"
        except Exception as exc:
            out[t] = f"failed: {exc}"
    return out
