"""Collector script download endpoint + network/ingress helpers.

GET  /collector/download        — return configured collect.py
GET  /network/interfaces        — discover candidate upload URLs
POST /collector/ingress         — create a K8s LoadBalancer service for external access
GET  /collector/ingress         — query status / external IP of the LB service
DELETE /collector/ingress       — remove the K8s LoadBalancer service
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
import zipfile
from datetime import UTC
from datetime import date as _date
from pathlib import Path

import redis_keys as rk
from auth.dependencies import require_admin, require_analyst_or_admin
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

logger = logging.getLogger(__name__)
router = APIRouter(tags=["collector"])

# ── Script discovery ──────────────────────────────────────────────────────────
# Order matters: check Docker-mounted path first, then local dev fallback.

_SCRIPT_CANDIDATES = [
    Path("/app/collector/collect.py"),  # docker-compose volume mount
    Path(__file__).parent.parent / "collector" / "collect.py",  # local: api/../collector/
    Path(__file__).parent.parent.parent / "collector" / "collect.py",  # mono-repo root
]

_INJECT_PATTERN = re.compile(
    r"^EMBEDDED_CONFIG\s*:\s*dict\s*=\s*\{\}",
    re.MULTILINE,
)


def _triage_minio(cfg: dict):
    """Build a Minio client from a triage S3 config dict (fo:s3_triage_config)."""
    from minio import Minio

    endpoint = cfg["endpoint"]
    for pfx in ("https://", "http://"):
        if endpoint.lower().startswith(pfx):
            endpoint = endpoint[len(pfx) :]
            break
    return Minio(
        endpoint,
        access_key=cfg.get("access_key", ""),
        secret_key=cfg.get("secret_key", ""),
        secure=cfg.get("use_ssl", True),
        region=cfg.get("region") or None,
    )


# Multipart provisioning tunables. 256 part slots at a 128 MiB target part size
# covers a ~32 GiB archive without growing the part size; larger archives get a
# proportionally larger part size (the collector recomputes from the real file
# size) up to the 256 × 5 GiB hard ceiling.
_MP_TARGET_PART = 128 * 1024 * 1024
_MP_MAX_PARTS = 256


def _provision_multipart(mc, bucket: str, key: str, expires):
    """Initiate an S3 multipart upload and presign every URL the offline
    collector needs — one PUT per part slot, plus complete and abort. Returns
    the baked config block, or ``None`` if the backend can't provision it (in
    which case the collector falls back to a single presigned PUT).

    Note: this creates a real multipart upload at package-download time. If the
    collector never runs, that leaves an incomplete upload on the bucket; a
    lifecycle rule (AbortIncompleteMultipartUpload) should sweep those, and the
    collector aborts its own upload on failure.
    """
    create = getattr(mc, "_create_multipart_upload", None)
    if create is None:
        logger.warning("minio client lacks _create_multipart_upload; multipart disabled")
        return None
    try:
        upload_id = create(bucket, key, {"Content-Type": "application/zip"})
        part_urls = [
            mc.get_presigned_url(
                "PUT",
                bucket,
                key,
                expires=expires,
                extra_query_params={"partNumber": str(n), "uploadId": upload_id},
            )
            for n in range(1, _MP_MAX_PARTS + 1)
        ]
        complete_url = mc.get_presigned_url(
            "POST", bucket, key, expires=expires, extra_query_params={"uploadId": upload_id}
        )
        abort_url = mc.get_presigned_url(
            "DELETE", bucket, key, expires=expires, extra_query_params={"uploadId": upload_id}
        )
        return {
            "key": key,
            "upload_id": upload_id,
            "part_urls": part_urls,
            "complete_url": complete_url,
            "abort_url": abort_url,
            "part_size": _MP_TARGET_PART,
            "parallelism": 4,
        }
    except Exception as exc:  # noqa: BLE001 — non-fatal, single PUT still works
        logger.warning("Could not provision multipart upload (large files disabled): %s", exc)
        return None


def _zwrite(zf: zipfile.ZipFile, name: str, data: bytes, exe: bool = False) -> None:
    """Write a zip member preserving the unix executable bit when requested.

    zipfile.writestr stores members without permission bits, which means files
    extracted on Linux/macOS arrive without their +x — fatal for the bundled
    python3 interpreter and the run.sh launcher. Constructing ZipInfo manually
    with external_attr = (mode << 16) preserves the bit through unzip."""
    info = zipfile.ZipInfo(name)
    info.compress_type = zipfile.ZIP_DEFLATED
    mode = 0o755 if exe else 0o644
    info.external_attr = (mode << 16) | (0x10 if name.endswith("/") else 0x00)
    zf.writestr(info, data)


def _find_collect_script() -> Path:
    for p in _SCRIPT_CANDIDATES:
        if p.exists():
            return p
    raise FileNotFoundError(
        "collect.py not found — checked: " + ", ".join(str(p) for p in _SCRIPT_CANDIDATES)
    )


def _inject_config(source: str, config: dict) -> str:
    repr_str = repr(config)
    replacement = f"EMBEDDED_CONFIG: dict = {repr_str}"
    # Callable replacement: repr() output can contain backslashes (Windows
    # paths, escaped quotes in tokens) that re would reinterpret as template
    # escapes and silently corrupt the embedded config.
    new_source, n = _INJECT_PATTERN.subn(lambda _m: replacement, source)
    if n == 0:
        logger.warning("EMBEDDED_CONFIG placeholder not found in collect.py")
    return new_source


# ── Download endpoint ─────────────────────────────────────────────────────────


@router.get("/s3-triage/status")
def s3_triage_status():
    """Presence-only S3 triage probe. Analysts hit this to decide whether to
    show the S3 upload affordances on the Collector page. Returns no creds."""
    from config import get_redis as _get_redis

    raw = _get_redis().get(rk.S3_TRIAGE_CONFIG)
    return {"configured": bool(raw)}


@router.get("/collector/python-embeds")
def list_python_embeds():
    """Return the list of bundleable Python interpreter targets with sizes."""
    from services.python_embeds import EMBED_TARGETS, _cache_path

    return {
        "targets": [
            {
                "id": tid,
                "label": spec.label,
                "size_mb": spec.size_mb,
                "cached": _cache_path(tid).exists(),
            }
            for tid, spec in EMBED_TARGETS.items()
        ],
    }


@router.post("/collector/python-embeds/warm")
def warm_python_embeds(targets: list[str] | None = None):
    """Pre-fetch one or more embed archives to the cache. Admin only."""
    from services.python_embeds import warm_cache

    return warm_cache(targets)


@router.get("/collector/download")
def download_collector(
    platform: str = Query(default="py", description="py | win | linux"),
    case_id: str | None = Query(default=None),
    api_url: str | None = Query(default=None),
    collect: str | None = Query(default=None),
    api_token: str | None = Query(
        default=None, description="JWT bearer token embedded in the script"
    ),
):
    """Return a configured collect.py script as a file download."""
    platform = platform.lower()
    if platform not in ("py", "win", "linux"):
        raise HTTPException(status_code=400, detail="platform must be 'py', 'win', or 'linux'")

    try:
        source = _find_collect_script().read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        logger.error("collect.py not found: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to read collect.py: %s", exc)
        raise HTTPException(status_code=500, detail="Could not load collector script")

    config: dict = {}
    if case_id:
        config["case_id"] = case_id
    if api_url:
        config["api_url"] = api_url.rstrip("/")
    if collect:
        config["collect"] = [k.strip() for k in collect.split(",") if k.strip()]
    if api_token:
        config["api_token"] = api_token

    return Response(
        content=_inject_config(source, config).encode("utf-8"),
        media_type="text/x-python",
        headers={
            "Content-Disposition": 'attachment; filename="fo-collector.py"',
            "Cache-Control": "no-store",
        },
    )


# ── ForensicsOperator Harvester package download ──────────────────────────────

# Complete ordered list of artifact categories supported by fo-harvester.py.
# Mode, input source (--path / --disk), and BitLocker key are CLI arguments —
# they are never stored in config.json.

# Per-platform artifact catalog now lives in Talon's capabilities.yaml
# (the tool owns it). Served via GET /collector/categories, built at request
# time from the Talon capability manifest — Citadel stays tool-agnostic.


# Map a capability platform id (windows/linux/macos) → the Collector UI's
# short key (win/linux/macos) the frontend expects.
_PLATFORM_TO_UI = {"windows": "win", "linux": "linux", "macos": "macos"}


def _build_catalog() -> dict[str, list[dict]]:
    """Per-platform artifact catalog, built ENTIRELY from Talon's capability
    manifest — categories, labels, descriptions AND their section ``group`` all
    come from the tool. Citadel holds zero artifact knowledge of its own."""
    catalog: dict[str, list[dict]] = {}
    try:
        from routers.tools import _aggregate

        talon = next((m for m in _aggregate() if m["tool"] == "talon"), None)
    except Exception:
        talon = None
    if not talon:
        return catalog
    for cap in talon.get("capabilities", []):
        plat = cap["key"].replace("collect_", "")
        ui_key = _PLATFORM_TO_UI.get(plat, plat)
        cats_field = next((f for f in cap.get("inputs", []) if f.get("name") == "categories"), None)
        if not cats_field:
            continue
        items = []
        for opt in cats_field.get("options", []):
            items.append({
                "key": opt.get("value", ""),
                "label": opt.get("label", opt.get("value", "")),
                "desc": opt.get("desc", ""),
                "group": opt.get("group", "Other"),  # the tool's own section hint
            })
        catalog[ui_key] = items
    return catalog


def _group_order(catalog: dict[str, list[dict]]) -> dict[str, list[str]]:
    """Section order per platform = order each group first appears in the tool's
    (already group-ordered) category list. No Citadel-side taxonomy."""
    out: dict[str, list[str]] = {}
    for plat, items in catalog.items():
        seen: list[str] = []
        for it in items:
            g = it.get("group", "Other")
            if g not in seen:
                seen.append(g)
        out[plat] = seen
    return out


def _valid_category_keys() -> set[str]:
    """Accepted category keys = whatever Talon advertises. Replaces the old
    hardcoded _ALL_CATEGORIES allow-list."""
    return {it["key"] for items in _build_catalog().values() for it in items}


# Pinned portable-Python versions — kept in sync with services.python_embeds so
# the runtime auto-download matches what the bundled (offline) embed would be.
from services.python_embeds import CPY_VERSION as _COLLECTOR_PYVER  # noqa: E402
from services.python_embeds import PBS_TAG as _COLLECTOR_PBS  # noqa: E402

# ── Reusable Python-provisioning snippets (versions baked at import) ──────────
# Strategy everywhere: bundled embed in the package → previously cached download
# → system Python → (unless --offline) download a portable Python and use it.
# Windows uses the python.org embeddable zip; macOS/Linux use the matching
# python-build-standalone install_only tarball.

_PROVISION_PS1 = r"""
function Resolve-FoPython {
    param([string]$BaseDir, [switch]$Offline)
    $bundled = Join-Path $BaseDir "python-embed\python.exe"
    if (Test-Path $bundled) { return $bundled }
    $cache = Join-Path $BaseDir ".python\python-embed\python.exe"
    if (Test-Path $cache) { return $cache }
    foreach ($cmd in @("python","python3","py")) {
        try { $v = & $cmd --version 2>&1; if ("$v" -match "Python 3") { return $cmd } } catch {}
    }
    if ($Offline) { throw "No Python found and -Offline set. Re-generate the package with Python bundled, or install Python 3." }
    Write-Host "  No Python found - downloading portable Python @@PYVER@@ ..." -ForegroundColor Yellow
    $url  = "https://www.python.org/ftp/python/@@PYVER@@/python-@@PYVER@@-embed-amd64.zip"
    $dest = Join-Path $BaseDir ".python\python-embed"
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    $tmp = Join-Path $env:TEMP ("fopy-" + [System.Guid]::NewGuid().ToString("N").Substring(0,8) + ".zip")
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    (New-Object System.Net.WebClient).DownloadFile($url, $tmp)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($tmp, $dest)
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    $py = Join-Path $dest "python.exe"
    if (-not (Test-Path $py)) { throw "Portable Python download/extract failed." }
    return $py
}
""".replace("@@PYVER@@", _COLLECTOR_PYVER)

_PROVISION_SH = r"""
fo_resolve_python() {
    # echoes a python path on stdout; returns 1 if none could be provisioned.
    base="$1"; offline="$2"
    [ -x "$base/python3/bin/python3" ] && { echo "$base/python3/bin/python3"; return 0; }
    [ -x "$base/.python/python/bin/python3" ] && { echo "$base/.python/python/bin/python3"; return 0; }
    for c in python3 python; do
        if command -v "$c" >/dev/null 2>&1; then
            case "$("$c" --version 2>&1)" in "Python 3"*) command -v "$c"; return 0 ;; esac
        fi
    done
    [ "$offline" = "1" ] && { echo "" ; return 1; }
    os="$(uname -s)"; arch="$(uname -m)"
    case "$os" in
      Linux)  case "$arch" in x86_64|amd64) triple="x86_64-unknown-linux-gnu" ;; aarch64|arm64) triple="aarch64-unknown-linux-gnu" ;; *) echo "" ; return 1 ;; esac ;;
      Darwin) case "$arch" in arm64) triple="aarch64-apple-darwin" ;; x86_64) triple="x86_64-apple-darwin" ;; *) echo "" ; return 1 ;; esac ;;
      *) echo "" ; return 1 ;;
    esac
    url="https://github.com/astral-sh/python-build-standalone/releases/download/@@PBS@@/cpython-@@PYVER@@+@@PBS@@-${triple}-install_only.tar.gz"
    echo "  No python3 found - downloading portable Python @@PYVER@@ (${triple}) ..." >&2
    mkdir -p "$base/.python"
    tb="$base/.python/py.tar.gz"
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$url" -o "$tb" || { echo "" ; return 1; }
    elif command -v wget >/dev/null 2>&1; then wget -q "$url" -O "$tb" || { echo "" ; return 1; }
    else echo "" ; return 1; fi
    tar -xzf "$tb" -C "$base/.python" || { echo "" ; return 1; }
    rm -f "$tb"
    [ -x "$base/.python/python/bin/python3" ] && { echo "$base/.python/python/bin/python3"; return 0; }
    echo "" ; return 1
}
""".replace("@@PYVER@@", _COLLECTOR_PYVER).replace("@@PBS@@", _COLLECTOR_PBS)

# run.bat — thin launcher; all logic (incl. Python provisioning) lives in run.ps1
# so Windows has one code path. Pass-through args; -Offline supported.
_RUN_BAT = """\
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
pause
"""

_RUN_PS1 = (
    """#Requires -Version 5.1
param([switch]$Offline)
$ErrorActionPreference = "Stop"
$DIR = $PSScriptRoot
Write-Host "ForensicsOperator Harvester - starting collection..."
"""
    + _PROVISION_PS1
    + """
$py = Resolve-FoPython -BaseDir $DIR -Offline:$Offline
Write-Host "Using Python: $py"
$rest = $args | Where-Object { $_ -ne "-Offline" }
& $py (Join-Path $DIR "fo-harvester.py") @rest
exit $LASTEXITCODE
"""
)

_RUN_SH = (
    """#!/bin/sh
# ForensicsOperator Harvester - run on Linux or macOS.
# Self-provisions Python: bundled -> system -> auto-download portable.
# Pass --offline to forbid the download and require a bundled/system Python.
DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
OFFLINE=0
for a in "$@"; do [ "$a" = "--offline" ] && OFFLINE=1; done
"""
    + _PROVISION_SH
    + """
PY="$(fo_resolve_python "$DIR" "$OFFLINE")"
if [ -z "$PY" ]; then
    echo "ERROR: no Python available and could not provision one." >&2
    echo "Install Python 3, run online, or use a package built with Python bundled." >&2
    exit 1
fi
echo "Using Python: $PY"
# Strip our own --offline flag before handing args to the harvester.
args=""
for a in "$@"; do [ "$a" = "--offline" ] || args="$args \\"$a\\""; done
eval exec "\\"$PY\\"" "\\"$DIR/fo-harvester.py\\"" $args
"""
)

_README = """\
ForensicsOperator Harvester — Self-contained collection package
================================================================

Python 3.8+ required — no additional packages needed.

Contents
--------
  fo-harvester.py   Standalone collector (reads artifact settings from config.json)
  config.json       Pre-filled artifact profile (true/false per category)
  run.bat           Windows launcher (double-click or run as Administrator)
  run.sh            Linux / macOS launcher

Step 1 — Copy to the target machine
--------------------------------------
  Transfer the fo-harvester/ folder to the target machine.

Step 2 — Run the collector
----------------------------
  Windows — live OS collection (run as Administrator):
      double-click run.bat
      — or —
      python fo-harvester.py

  Linux / macOS — live OS collection (run as root):
      chmod +x run.sh && ./run.sh
      — or —
      python3 fo-harvester.py

  Dead-box: already-mounted directory (any OS):
      python fo-harvester.py --path D:\\
      python3 fo-harvester.py --path /mnt/windows

  Dead-box: raw block device — Linux only (ntfs-3g required):
      python3 fo-harvester.py --disk /dev/sdb1

  BitLocker-encrypted drive — key stays local, never stored in config.json:
      python fo-harvester.py --path E:\\ --bitlocker-key 123456-123456-...
      python3 fo-harvester.py --disk /dev/sdb1 --bitlocker-key 123456-123456-...

  Override output path:
      python fo-harvester.py --output C:\\evidence\\output.zip

  Override artifact selection (comma-separated, overrides config.json):
      python fo-harvester.py --collect evtx,registry,prefetch

Step 3 — Upload results to ForensicsOperator
---------------------------------------------
  A ZIP archive is created in ./output/ (or --output path).
  Upload it via:  Case → Ingest tab → Upload ZIP
"""


@router.get("/collector/categories", dependencies=[Depends(require_analyst_or_admin)])
def list_collector_categories():
    """
    Authoritative artifact catalog for the collector wizard.

    Built from Talon's capability manifest (the tool owns the catalog) + this
    file's section taxonomy. The frontend renders from this, so it always
    reflects what Talon declares — no hardcoded copy to drift.
    Read-only; auth-gated to analyst/admin. No user input → no injection surface.
    """
    catalog = _build_catalog()
    return {
        "platforms": catalog,
        "group_order": _group_order(catalog),
        "all": sorted({it["key"] for items in catalog.values() for it in items}),
    }


@router.get("/collector/package")
def download_harvester_package(
    categories: str | None = Query(
        default=None,
        description="Comma-separated enabled category keys.",
    ),
    case_name: str | None = Query(default=None),
    path: str | None = Query(
        default=None,
        description="Dead-box: already-mounted filesystem root (e.g. /mnt/evidence or E:\\)",
    ),
    disk: str | None = Query(
        default=None, description="Dead-box: raw block device to mount (Linux only, e.g. /dev/sdb1)"
    ),
    skip_problematic: bool = Query(
        default=False, description="Auto-skip artifact categories known to fail in dead-box mode"
    ),
    fetch_patterns: str | None = Query(
        default=None,
        description="file_search patterns, newline- or comma-separated. "
        "Syntax per entry: 'name', glob ('*.ps1'), or 're:<regex>'.",
    ),
    fetch_max_files: int | None = Query(
        default=None, description="file_search: max files fetched (default 200)"
    ),
    fetch_max_mb: int | None = Query(
        default=None, description="file_search: max size per fetched file in MB (default 100)"
    ),
    output_dir: str = Query(default="./output"),
    api_url: str | None = Query(default=None),
    case_id: str | None = Query(default=None),
    api_token: str | None = Query(default=None),
    platform: str | None = Query(
        default=None, description="Target OS label: win, linux, deadbox, etc."
    ),
    upload_mode: str | None = Query(
        default=None, description="'s3_presigned' to embed a presigned S3 PUT URL"
    ),
    presign_expires_hours: int = Query(
        default=24, description="Presigned URL TTL in hours (1–168)"
    ),
    include_python: str | None = Query(
        default=None,
        description="Embed a portable Python interpreter so the target needs none installed. "
        "Values: 'win-x64' | 'linux-x64' | 'linux-arm64' | 'macos'. "
        "Adds 7-28 MB to the zip.",
    ),
):
    """
    Return a self-contained ZIP: fo-harvester.py + config.json + launch scripts.
    All parameters are baked into config.json — run with zero arguments on target.
    BitLocker key is never stored; pass --bitlocker-key on the target if needed.
    """
    enabled = [c.strip() for c in categories.split(",") if c.strip()] if categories else []

    config: dict = {
        "collect": enabled,
        "output_dir": output_dir or "./output",
    }
    if case_name:
        config["case_name"] = case_name.strip()
    if path:
        config["path"] = path.strip()
    if disk:
        config["disk"] = disk.strip()
    if skip_problematic:
        config["skip_problematic"] = True
    _patterns = (
        [p.strip() for p in re.split(r"[\n,]", fetch_patterns) if p.strip()]
        if fetch_patterns
        else []
    )
    if _patterns:
        config["fetch_patterns"] = _patterns
        if "file_search" not in enabled:
            enabled.append("file_search")
            config["collect"] = enabled
    if fetch_max_files:
        config["fetch_max_files"] = int(fetch_max_files)
    if fetch_max_mb:
        config["fetch_max_mb"] = int(fetch_max_mb)
    if api_url:
        config["api_url"] = api_url.strip()
    if case_id:
        config["case_id"] = case_id.strip()
    if api_token:
        config["api_token"] = api_token.strip()

    # Generate and bake a presigned S3 PUT URL when requested
    if upload_mode == "s3_presigned":
        import re as _re2
        from datetime import datetime as _dt
        from datetime import timedelta as _td

        from config import get_redis as _get_redis

        _r = _get_redis()
        _raw_s3 = _r.get(rk.S3_TRIAGE_CONFIG)
        if not _raw_s3:
            raise HTTPException(
                status_code=404,
                detail="No S3 triage config saved. Configure it in Admin → S3 Triage Upload first.",
            )
        _s3cfg = json.loads(_raw_s3)
        _mc = _triage_minio(_s3cfg)
        _ts = _dt.now(UTC).strftime("%Y%m%d-%H%M%S")
        _cn_slug = _re2.sub(r"[^\w.\-]", "_", (case_name or "collection").strip())[:60]
        _key = f"uploads/{_ts}-{_cn_slug}.zip"
        _log_key = f"uploads/{_ts}-{_cn_slug}.collector.log"
        _expires = _td(hours=max(1, min(presign_expires_hours, 168)))
        try:
            config["presigned_url"] = _mc.presigned_put_object(
                _s3cfg["bucket"], _key, expires=_expires
            )
            # Second URL: the execution log lands next to the archive in S3 so a
            # crashed / killed / empty-archive run still leaves a post-mortem.
            config["presigned_log_url"] = _mc.presigned_put_object(
                _s3cfg["bucket"], _log_key, expires=_expires
            )
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Could not generate presigned URL: {exc}")

        # Provision a full multipart upload so the offline collector can ship
        # archives larger than the 5 GiB single-PUT ceiling — and upload big
        # files as many small, parallel, retryable parts (robust on slow/flaky
        # WAN links). Every URL is presigned now because the collector has no
        # API connectivity at runtime. Best-effort: if provisioning fails the
        # package still ships and simply falls back to the single PUT.
        _mp = _provision_multipart(_mc, _s3cfg["bucket"], _key, _expires)
        if _mp:
            config["multipart_upload"] = _mp

    try:
        script_bytes = _find_collect_script().read_bytes()
    except FileNotFoundError as exc:
        logger.error("collect.py not found for package: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc))

    # Compute folder/filename before creating the zip so the internal
    # directory matches the zip stem (unzipping produces a same-named folder).
    parts = ["fo-collector"]
    if case_name:
        safe = re.sub(r"[^\w\s-]", "", case_name).strip().lower()
        safe = re.sub(r"[\s_]+", "-", safe)[:40]
        if safe:
            parts.append(safe)
    if platform:
        safe_plat = re.sub(r"[^\w-]", "", platform.strip().lower())[:16]
        if safe_plat:
            parts.append(safe_plat)
    parts.append(_date.today().isoformat())  # YYYY-MM-DD
    folder = "_".join(parts)
    filename = folder + ".zip"

    # Embed Python target choice — windows uses python-embed/, *nix uses python3/
    py_folder_prefix = {
        "win-x64": "python-embed",
        "linux-x64": "python3",
        "linux-arm64": "python3",
        "macos": "python3",
    }.get((include_python or "").strip().lower())

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        _zwrite(zf, f"{folder}/fo-harvester.py", script_bytes, exe=False)
        _zwrite(
            zf, f"{folder}/config.json", json.dumps(config, indent=2).encode("utf-8"), exe=False
        )
        _zwrite(zf, f"{folder}/run.bat", _RUN_BAT.encode("utf-8"), exe=False)
        _zwrite(zf, f"{folder}/run.ps1", _RUN_PS1.encode("utf-8"), exe=False)
        _zwrite(zf, f"{folder}/run.sh", _RUN_SH.encode("utf-8"), exe=True)
        _zwrite(zf, f"{folder}/README.txt", _README.encode("utf-8"), exe=False)

        if py_folder_prefix:
            try:
                from services.python_embeds import iter_embed_members

                for member_name, data, exe in iter_embed_members(
                    (include_python or "").strip().lower(),
                    folder_prefix=f"{folder}/{py_folder_prefix}",
                ):
                    _zwrite(zf, member_name, data, exe=exe)
            except Exception as exc:
                logger.error("Failed to embed Python (%s): %s", include_python, exc)
                raise HTTPException(
                    status_code=502,
                    detail=f"Could not bundle Python embed: {exc}",
                )

    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


# ── fo-uploader package download ─────────────────────────────────────────────

_UPLOADER_CANDIDATES = [
    Path("/app/collector/fo_uploader.py"),  # docker
    Path(__file__).parent.parent / "collector" / "fo_uploader.py",  # api/../collector/
    Path(__file__).parent.parent.parent / "collector" / "fo_uploader.py",  # mono-repo root
]

_UPLOADER_REQUIREMENTS = "boto3\n"

_UPLOADER_RUN_BAT = """\
@echo off
echo Installing dependencies...
pip install boto3
echo.
echo Uploading artifacts...
python fo-uploader.py
pause
"""

_UPLOADER_RUN_SH = """\
#!/bin/sh
echo "Installing dependencies..."
pip3 install boto3
echo
echo "Uploading artifacts..."
python3 fo-uploader.py
"""

_UPLOADER_README = """\
fo-uploader — S3 Evidence Uploader
====================================

Uploads fo-harvester artifacts (fo-artifacts-*.zip) to the configured S3 bucket.
Pre-filled with your ForensicsOperator S3 triage configuration.

WARNING: This script contains your S3 credentials.
         Do not share it or commit it to source control.

Requirements
------------
  pip install boto3      (or: pip3 install boto3)

Usage
-----
  1. Run fo-harvester.py to collect artifacts → creates ./output/fo-artifacts-*.zip
  2. Run fo-uploader.py (or the included run.bat / run.sh):

       Windows:
           run.bat
           — or —
           pip install boto3 && python fo-uploader.py

       Linux / macOS:
           chmod +x run.sh && ./run.sh
           — or —
           pip3 install boto3 && python3 fo-uploader.py

Options
-------
  --file PATH      Upload a specific file instead of auto-detecting
  --dir  DIR       Directory to scan for fo-artifacts-*.zip (default: ./output)
  --prefix PREFIX  S3 key prefix / sub-folder inside the bucket

After upload, open ForensicsOperator → Admin → S3 Triage browser,
locate the file, and pull it into a case for analysis.
"""


def _find_uploader_script() -> Path:
    for p in _UPLOADER_CANDIDATES:
        if p.exists():
            return p
    raise FileNotFoundError(
        "fo_uploader.py not found — checked: " + ", ".join(str(p) for p in _UPLOADER_CANDIDATES)
    )


def _inject_uploader_config(source: str, cfg: dict) -> str:
    """Inject S3 credentials into fo_uploader.py (legacy mode)."""
    use_ssl_str = "true" if cfg.get("use_ssl", True) else "false"
    replacements = [
        ('ENDPOINT   = ""', f"ENDPOINT   = {json.dumps(cfg.get('endpoint', ''))}"),
        ('ACCESS_KEY = ""', f"ACCESS_KEY = {json.dumps(cfg.get('access_key', ''))}"),
        ('SECRET_KEY = ""', f"SECRET_KEY = {json.dumps(cfg.get('secret_key', ''))}"),
        ('BUCKET     = ""', f"BUCKET     = {json.dumps(cfg.get('bucket', ''))}"),
        ('REGION     = ""', f"REGION     = {json.dumps(cfg.get('region', ''))}"),
        ('USE_SSL    = "true"', f"USE_SSL    = {json.dumps(use_ssl_str)}"),
    ]
    for old, new in replacements:
        source = source.replace(old, new, 1)
    return source


def _inject_presigned_config(source: str, presigned_urls: list, multipart_uploads=None) -> str:
    """Inject pre-signed PUT URLs (and optional multipart sessions, one per file
    slot) into fo_uploader.py (preferred mode — no credentials)."""
    urls_repr = "[" + ", ".join(json.dumps(u) for u in presigned_urls) + "]"
    out = source.replace("PRESIGNED_URLS = []", f"PRESIGNED_URLS = {urls_repr}", 1)
    return out.replace(
        "MULTIPART_UPLOADS = []", f"MULTIPART_UPLOADS = {json.dumps(multipart_uploads or [])}", 1
    )


@router.get("/collector/uploader", dependencies=[Depends(require_admin)])
def download_uploader_package():
    """
    Return a pre-configured fo-uploader.zip with S3 triage credentials injected.

    Admin-only: the ZIP contains the raw S3 secret key for the triage upload bucket.
    Requires the S3 triage config to be saved in Admin → S3 Triage Upload.
    """
    from config import get_redis as _get_redis

    r = _get_redis()
    raw = r.get(rk.S3_TRIAGE_CONFIG)
    if not raw:
        raise HTTPException(
            status_code=404,
            detail="No S3 triage upload config saved. Configure it in Admin → S3 Triage Upload first.",
        )
    cfg = json.loads(raw)

    try:
        source = _find_uploader_script().read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        logger.error("fo_uploader.py not found: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to read fo_uploader.py: %s", exc)
        raise HTTPException(status_code=500, detail="Could not load uploader script")

    injected = _inject_uploader_config(source, cfg)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr("fo-uploader/fo-uploader.py", injected.encode("utf-8"))
        zf.writestr("fo-uploader/requirements.txt", _UPLOADER_REQUIREMENTS)
        zf.writestr("fo-uploader/run.bat", _UPLOADER_RUN_BAT)
        zf.writestr("fo-uploader/run.sh", _UPLOADER_RUN_SH)
        zf.writestr("fo-uploader/README.txt", _UPLOADER_README)

    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="fo-uploader.zip"',
            "Cache-Control": "no-store",
        },
    )


_PRESIGNED_README = """\
fo-uploader (pre-signed URL mode) — S3 Evidence Uploader
==========================================================

This script uploads up to 3 fo-harvester artifact ZIPs to the evidence S3 bucket
using pre-signed URLs. No S3 credentials are stored in the script.

Each URL is a one-time write slot for a unique S3 key — the script pairs each
found ZIP with one slot (first file → slot 1, second → slot 2, etc.).

The pre-signed URLs are valid for a limited time (see expires_at below).
After they expire, download a fresh copy from ForensicsOperator → Collector.

Requirements
------------
  Python 3.6+  — no third-party packages needed (uses stdlib only).

Usage
-----
  python fo-uploader.py                      # auto-detect ./output/fo-artifacts-*.zip
  python fo-uploader.py --file evidence.zip  # upload a specific file
  python fo-uploader.py --dir ./output       # scan a directory

After upload, open ForensicsOperator → Admin → S3 Triage browser,
locate the file, and pull it into a case for analysis.

Security
--------
  The pre-signed URL grants a one-time PUT to a single S3 key.
  It cannot list, read, or delete any objects in the bucket.
  Safe to distribute — does not expose your S3 credentials.

Chain of Custody
----------------
  The script prints a SHA-256 hash before each upload.
  Record this hash — it proves the file was not modified after upload.
"""

_PRESIGNED_RUN_BAT = """\
@echo off
echo Uploading artifacts via pre-signed URL (no credentials needed)...
python fo-uploader.py
pause
"""

_PRESIGNED_RUN_SH = """\
#!/bin/sh
echo "Uploading artifacts via pre-signed URL (no credentials needed)..."
python3 fo-uploader.py
"""


@router.post("/collector/uploader-presign", dependencies=[Depends(require_analyst_or_admin)])
def download_uploader_presigned(
    filename: str = "fo-artifacts.zip",
    expires_hours: int = 24,
    count: int = 3,
):
    """
    Generate up to 3 pre-signed PUT URLs and return a configured fo-uploader.zip.

    Each URL is a unique one-time write slot — the script can upload up to `count`
    files (one per slot). No S3 credentials are embedded. Suitable for distribution
    to field operators without exposing the triage bucket credentials.

    Requires the S3 triage config to be saved in Admin → S3 Triage Upload.
    """
    import re as _re
    from datetime import datetime, timedelta

    from config import get_redis as _get_redis

    count = max(1, min(count, 3))

    r = _get_redis()
    raw = r.get(rk.S3_TRIAGE_CONFIG)
    if not raw:
        raise HTTPException(
            status_code=404,
            detail="No S3 triage config saved. Configure it in Admin → S3 Triage Upload first.",
        )
    cfg = json.loads(raw)
    client = _triage_minio(cfg)

    import uuid as _uuid

    ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    safe_name = _re.sub(r"[^\w.\-]", "_", filename)[:80]
    expires = timedelta(hours=max(1, min(expires_hours, 168)))

    presigned_urls = []
    keys = []
    multipart_uploads = []
    try:
        for i in range(count):
            uid = _uuid.uuid4().hex[:8]
            key = f"uploads/{ts}-{uid}-slot{i + 1}-{safe_name}"
            url = client.presigned_put_object(cfg["bucket"], key, expires=expires)
            presigned_urls.append(url)
            keys.append(key)
            # Provision a multipart session per slot so files over the 5 GiB
            # single-PUT ceiling can still be uploaded (best-effort; None falls
            # back to the single PUT).
            multipart_uploads.append(_provision_multipart(client, cfg["bucket"], key, expires))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not generate presigned URL: {exc}")

    expires_at = (datetime.now(UTC) + expires).isoformat()

    try:
        source = _find_uploader_script().read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    injected = _inject_presigned_config(source, presigned_urls, multipart_uploads)

    slot_lines = "\n".join(f"  Slot {i + 1}: {cfg['bucket']}/{k}" for i, k in enumerate(keys))
    readme = (
        _PRESIGNED_README
        + f"\nExpires at : {expires_at}\n"
        + f"Upload slots ({count}):\n{slot_lines}\n"
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr("fo-uploader/fo-uploader.py", injected.encode("utf-8"))
        zf.writestr("fo-uploader/run.bat", _PRESIGNED_RUN_BAT)
        zf.writestr("fo-uploader/run.sh", _PRESIGNED_RUN_SH)
        zf.writestr("fo-uploader/README.txt", readme)

    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="fo-uploader-presigned.zip"',
            "Cache-Control": "no-store",
        },
    )


# ── S3 bootstrap: upload collector zip to S3, return tiny fetch+run+cleanup scripts ──

_BOOTSTRAP_PS1 = """\
#Requires -Version 5.1
<#
.SYNOPSIS
    ForensicsOperator - S3 Bootstrap Collector
    Generated : TPLGENERATED_AT
    Expires   : TPLEXPIRES_AT
    Case      : TPLCASE_NAME
.DESCRIPTION
    Downloads the pre-packaged collector from S3, runs collection and evidence
    upload, then deletes the local temp directory and the collector package
    from S3.  Run as Administrator for complete artifact collection.
.PARAMETER Local
    Save collected ZIP locally instead of uploading to evidence storage.
.PARAMETER NoCleanup
    Keep temp directory after completion (useful for debugging).
.PARAMETER NoS3Cleanup
    Skip deleting the collector package from S3 after completion.
#>
param(
    [switch]$Local,
    [switch]$NoCleanup,
    [switch]$NoS3Cleanup,
    [switch]$Offline
)

$ErrorActionPreference = "Stop"

$COLLECTOR_URL = "TPLCOLLECTOR_URL"
$DELETE_URL    = "TPLDELETE_URL"
$EXPIRES_AT    = "TPLEXPIRES_AT"
$CASE_NAME     = "TPLCASE_NAME"

Write-Host ""
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "  ForensicsOperator - S3 Bootstrap Collector"                 -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
if ($CASE_NAME)  { Write-Host "  Case    : $CASE_NAME"  }
if ($EXPIRES_AT) { Write-Host "  Expires : $EXPIRES_AT" }
Write-Host ""

# ── Resolve Python (bundled / system / auto-download portable) ─────────────────
# @@PROVISION_PS1@@
$python = Resolve-FoPython -BaseDir $env:TEMP -Offline:$Offline
Write-Host "  Python  : $python" -ForegroundColor Green

# ── Temp directory ────────────────────────────────────────────────────────────
$tmpDir  = Join-Path $env:TEMP ("fo-bootstrap-" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8))
$zipPath = $tmpDir + ".zip"
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

try {
    # ── Download collector package from S3 ───────────────────────────────────
    Write-Host "  Downloading collector package..." -ForegroundColor Yellow
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($COLLECTOR_URL, $zipPath)
    $sizeMB = [Math]::Round((Get-Item $zipPath).Length / 1MB, 2)
    Write-Host "  Downloaded: $sizeMB MB" -ForegroundColor Green

    # ── Extract ──────────────────────────────────────────────────────────────
    Write-Host "  Extracting..." -ForegroundColor Yellow
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $tmpDir)
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

    # ── Find inner folder (zip may contain a single top-level directory) ─────
    $inner   = Get-ChildItem $tmpDir -Directory | Select-Object -First 1
    $workDir = if ($inner) { $inner.FullName } else { $tmpDir }

    # ── Run collection (fo-harvester.py reads config.json automatically) ─────
    Write-Host "  Running collection..." -ForegroundColor Yellow
    $prevDir = Get-Location
    Set-Location $workDir
    try {
        if ($Local) {
            & $python fo-harvester.py --output ".\\output"
        } else {
            & $python fo-harvester.py
        }
        if ($LASTEXITCODE -ne 0) { throw "fo-harvester.py exited with code $LASTEXITCODE" }
    } finally {
        Set-Location $prevDir
    }
    Write-Host "  Collection complete." -ForegroundColor Green

} finally {
    # ── Local cleanup ─────────────────────────────────────────────────────────
    if (-not $NoCleanup) {
        Remove-Item -Recurse -Force $tmpDir  -ErrorAction SilentlyContinue
        Remove-Item -Force         $zipPath -ErrorAction SilentlyContinue
        Write-Host "  Local temp files removed." -ForegroundColor Green
    }

    # ── S3 cleanup — delete the collector package so it cannot be replayed ────
    if ($DELETE_URL -and -not $NoS3Cleanup) {
        try {
            $client   = [System.Net.Http.HttpClient]::new()
            $client.Timeout = [TimeSpan]::FromSeconds(30)
            $req      = [System.Net.Http.HttpRequestMessage]::new(
                            [System.Net.Http.HttpMethod]::Delete, $DELETE_URL)
            $resp     = $client.SendAsync($req).GetAwaiter().GetResult()
            $code     = [int]$resp.StatusCode
            if ($code -ge 200 -and $code -lt 300 -or $code -eq 204) {
                Write-Host "  Collector package deleted from S3." -ForegroundColor Green
            } else {
                Write-Host "  Warning: S3 DELETE returned HTTP $code" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  Warning: S3 cleanup failed: $_" -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host "  Chain of custody hash (if printed above): record the SHA-256."
Write-Host "=============================================================" -ForegroundColor Cyan
if ($DELETE_URL -and -not $NoS3Cleanup) {
    Write-Host "  Done. Evidence uploaded to storage. Collector package removed." -ForegroundColor Cyan
} else {
    Write-Host "  Done." -ForegroundColor Cyan
}
Write-Host "=============================================================" -ForegroundColor Cyan
"""

_BOOTSTRAP_SH = r"""#!/usr/bin/env bash
# ForensicsOperator - S3 Bootstrap Collector
# Generated : TPLGENERATED_AT
# Expires   : TPLEXPIRES_AT
# Case      : TPLCASE_NAME
#
# Usage:
#   sudo bash fo-bootstrap.sh                        # live collection + upload
#   sudo bash fo-bootstrap.sh --path /mnt/windows    # dead-box: mounted disk
#   sudo bash fo-bootstrap.sh --local                # collect + save locally (no upload)
#   sudo bash fo-bootstrap.sh --no-s3-del            # skip S3 cleanup after upload
#
# Requires: Python 3.6+, curl or wget, unzip

set -euo pipefail

COLLECTOR_URL="TPLCOLLECTOR_URL"
DELETE_URL="TPLDELETE_URL"
EXPIRES_AT="TPLEXPIRES_AT"
CASE_NAME="TPLCASE_NAME"
LOCAL=0
NO_S3_DEL=0
OFFLINE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --local)     LOCAL=1;     shift ;;
        --no-s3-del) NO_S3_DEL=1; shift ;;
        --offline)   OFFLINE=1;   shift ;;
        *)           shift ;;
    esac
done

echo ""
echo "============================================================="
echo "  ForensicsOperator - S3 Bootstrap Collector"
echo "============================================================="
[ -n "$CASE_NAME"  ] && echo "  Case    : $CASE_NAME"
[ -n "$EXPIRES_AT" ] && echo "  Expires : $EXPIRES_AT"
echo ""

# ── Resolve Python (bundled / system / auto-download portable) ───────────────
# @@PROVISION_SH@@
PYTHON="$(fo_resolve_python "${TMPDIR:-/tmp}/fo-python" "$OFFLINE")"
if [ -z "$PYTHON" ]; then
    echo "ERROR: no Python available and could not provision one." >&2
    echo "Install Python 3, run online, or use --offline with a bundled Python." >&2
    exit 1
fi
echo "  Python  : $PYTHON"

# ── Temp directory (auto-cleaned on exit) ────────────────────────────────────
WORKDIR=$(mktemp -d)
ZIPFILE="$WORKDIR/fo-collector.zip"
trap 'rm -rf "$WORKDIR"' EXIT

# ── Download collector package from S3 ────────────────────────────────────────
echo "  Downloading collector package..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$ZIPFILE" "$COLLECTOR_URL"
elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$ZIPFILE" "$COLLECTOR_URL"
else
    echo "ERROR: neither curl nor wget found." >&2; exit 1
fi
SIZE=$(du -sh "$ZIPFILE" 2>/dev/null | cut -f1 || echo "?")
echo "  Downloaded: $SIZE"

# ── Extract ────────────────────────────────────────────────────────────────────
echo "  Extracting..."
unzip -q "$ZIPFILE" -d "$WORKDIR"
rm -f "$ZIPFILE"

# ── Find inner folder ─────────────────────────────────────────────────────────
INNER=$(find "$WORKDIR" -maxdepth 1 -mindepth 1 -type d | head -1 || true)
RUNDIR="${INNER:-$WORKDIR}"

# ── Run collection ─────────────────────────────────────────────────────────────
echo "  Running collection..."
if [ "$LOCAL" -eq 1 ]; then
    (cd "$RUNDIR" && "$PYTHON" fo-harvester.py --output "./output")
else
    (cd "$RUNDIR" && "$PYTHON" fo-harvester.py)
fi
echo "  Collection complete."

# ── S3 cleanup — delete the collector package so it cannot be replayed ────────
# (local WORKDIR is removed automatically by the trap on EXIT)
if [ -n "$DELETE_URL" ] && [ "$NO_S3_DEL" -eq 0 ]; then
    if command -v curl >/dev/null 2>&1; then
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$DELETE_URL" || echo "0")
        if echo "$HTTP_CODE" | grep -qE "^2|^204"; then
            echo "  Collector package deleted from S3."
        else
            echo "  Warning: S3 DELETE returned HTTP $HTTP_CODE" >&2
        fi
    else
        echo "  Warning: curl not found, skipping S3 cleanup." >&2
    fi
fi

echo ""
echo "  Chain of custody hash (if printed above): record the SHA-256."
echo "============================================================="
if [ -n "$DELETE_URL" ] && [ "$NO_S3_DEL" -eq 0 ]; then
    echo "  Done. Evidence uploaded to storage. Collector package removed."
else
    echo "  Done."
fi
echo "============================================================="
"""

# Inject the shared Python-provisioning logic into the bootstrap scripts so a
# target with NO Python still works: the script auto-downloads a portable
# interpreter (unless --offline / -Offline).
_BOOTSTRAP_PS1 = _BOOTSTRAP_PS1.replace("# @@PROVISION_PS1@@", _PROVISION_PS1)
_BOOTSTRAP_SH = _BOOTSTRAP_SH.replace("# @@PROVISION_SH@@", _PROVISION_SH)


@router.get("/collector/s3-bootstrap", dependencies=[Depends(require_analyst_or_admin)])
def download_s3_bootstrap(
    categories: str | None = Query(
        default=None, description="Comma-separated artifact categories. All enabled if omitted."
    ),
    case_name: str | None = Query(default=None),
    case_id: str | None = Query(default=None),
    api_url: str | None = Query(default=None),
    api_token: str | None = Query(default=None),
    expires_hours: int = Query(default=24, description="URL expiry in hours (1-168)"),
    platform: str = Query(default="zip", description="ps1 | sh | zip (both)"),
    path_arg: str | None = Query(
        default=None, description="Dead-box mount path injected into SH script (e.g. /mnt/windows)"
    ),
    disk_arg: str | None = Query(
        default=None, description="Raw disk/image path injected into SH script (e.g. /dev/sdb)"
    ),
    bitlocker_key: str | None = Query(
        default=None,
        description="BitLocker recovery key — baked into SH script, passed to fo-harvester",
    ),
    fetch_patterns: str | None = Query(
        default=None,
        description="file_search patterns, newline- or comma-separated ('name' / glob / 're:<regex>').",
    ),
):
    """
    Upload a pre-configured collector package to the S3 triage bucket, then return
    a lightweight bootstrap script (PS1 / SH / both) that:
      1. Downloads the collector zip from S3
      2. Extracts and runs fo-harvester.py (collects + uploads evidence)
      3. Deletes the local temp directory
      4. Deletes the collector zip from S3 (so it cannot be replayed)

    Requires the S3 triage config to be saved in Admin → S3 Triage Upload.
    """
    import re as _re
    import uuid as _uuid
    from datetime import datetime, timedelta

    platform = platform.lower()
    if platform not in ("ps1", "sh", "zip"):
        raise HTTPException(status_code=400, detail="platform must be ps1, sh, or zip")

    from config import get_redis as _get_redis

    r = _get_redis()
    raw = r.get(rk.S3_TRIAGE_CONFIG)
    if not raw:
        raise HTTPException(
            status_code=404,
            detail="No S3 triage config saved. Configure it in Admin → S3 Triage Upload first.",
        )
    s3cfg = json.loads(raw)
    mc = _triage_minio(s3cfg)
    bucket = s3cfg["bucket"]

    expires = timedelta(hours=max(1, min(expires_hours, 168)))
    now = datetime.now(UTC)
    ts = now.strftime("%Y%m%d-%H%M%S")
    safe_cn = _re.sub(r"[^\w.\-]", "_", (case_name or "collection").strip())[:60]

    # ── Build collector config (baked into the zip) ───────────────────────────
    enabled: list = [c.strip() for c in categories.split(",") if c.strip()] if categories else []
    config: dict = {"collect": enabled, "output_dir": "./output"}
    if case_name:
        config["case_name"] = case_name.strip()
    if api_url:
        config["api_url"] = api_url.strip()
    if case_id:
        config["case_id"] = case_id.strip()
    if api_token:
        config["api_token"] = api_token.strip()
    if path_arg:
        config["path"] = path_arg.strip()
    if disk_arg:
        config["disk"] = disk_arg.strip()
    if bitlocker_key:
        config["bitlocker_key"] = bitlocker_key.strip()
    _patterns = (
        [p.strip() for p in _re.split(r"[\n,]", fetch_patterns) if p.strip()]
        if fetch_patterns
        else []
    )
    if _patterns:
        config["fetch_patterns"] = _patterns
        if "file_search" not in enabled:
            enabled.append("file_search")
            config["collect"] = enabled

    # Generate a presigned PUT URL for evidence upload (baked into config.json)
    evidence_key = f"uploads/{ts}-{safe_cn}-evidence.zip"
    try:
        config["presigned_url"] = mc.presigned_put_object(bucket, evidence_key, expires=expires)
    except Exception as exc:
        logger.warning("Could not generate evidence presigned URL: %s", exc)
    # Multipart upload for archives over the 5 GiB single-PUT ceiling (see
    # _provision_multipart). Best-effort: falls back to the single PUT above.
    _mp = _provision_multipart(mc, bucket, evidence_key, expires)
    if _mp:
        config["multipart_upload"] = _mp

    # ── Build the collector zip ───────────────────────────────────────────────
    try:
        script_bytes = _find_collect_script().read_bytes()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    parts = ["fo-collector"]
    if case_name:
        safe = _re.sub(r"[^\w\s-]", "", case_name).strip().lower()
        safe = _re.sub(r"[\s_]+", "-", safe)[:40]
        if safe:
            parts.append(safe)
    parts.append(now.strftime("%Y-%m-%d"))
    folder = "_".join(parts)

    pkg_buf = io.BytesIO()
    with zipfile.ZipFile(pkg_buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr(f"{folder}/fo-harvester.py", script_bytes)
        zf.writestr(f"{folder}/config.json", json.dumps(config, indent=2))
        zf.writestr(f"{folder}/run.bat", _RUN_BAT)
        zf.writestr(f"{folder}/run.ps1", _RUN_PS1)
        zf.writestr(f"{folder}/run.sh", _RUN_SH)
    pkg_bytes = pkg_buf.getvalue()

    # ── Upload collector zip to S3 ────────────────────────────────────────────
    collector_key = f"bootstrap/{ts}-{_uuid.uuid4().hex[:8]}-{safe_cn}.zip"
    try:
        mc.put_object(
            bucket,
            collector_key,
            io.BytesIO(pkg_bytes),
            len(pkg_bytes),
            content_type="application/zip",
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not upload collector to S3: {exc}")

    # ── Presigned GET URL (bootstrap downloads from this) ─────────────────────
    try:
        collector_get_url = mc.presigned_get_object(bucket, collector_key, expires=expires)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not generate download URL: {exc}")

    # ── Presigned DELETE URL (bootstrap calls this after collection) ──────────
    delete_url = ""
    try:
        delete_url = mc.get_presigned_url("DELETE", bucket, collector_key, expires=expires)
    except Exception as exc:
        logger.warning("Could not generate presigned DELETE URL: %s", exc)

    expires_at = (now + expires).isoformat()
    now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    cn = case_name or ""

    def _fill(template: str) -> bytes:
        return (
            template.replace("TPLGENERATED_AT", now_str)
            .replace("TPLEXPIRES_AT", expires_at)
            .replace("TPLCASE_NAME", cn)
            .replace("TPLCOLLECTOR_URL", collector_get_url)
            .replace("TPLDELETE_URL", delete_url)
        ).encode("utf-8")

    safe_name = _re.sub(r"[^\w-]", "_", cn)[:30]
    ts_short = now.strftime("%Y%m%d")
    base_name = f"fo-bootstrap-{safe_name}-{ts_short}" if safe_name else f"fo-bootstrap-{ts_short}"

    if platform == "ps1":
        return Response(
            content=_fill(_BOOTSTRAP_PS1),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{base_name}.ps1"',
                "Cache-Control": "no-store",
            },
        )
    if platform == "sh":
        return Response(
            content=_fill(_BOOTSTRAP_SH),
            media_type="application/x-sh",
            headers={
                "Content-Disposition": f'attachment; filename="{base_name}.sh"',
                "Cache-Control": "no-store",
            },
        )

    readme = (
        f"ForensicsOperator S3 Bootstrap Collector\n"
        f"Generated : {now_str}\n"
        f"Case      : {cn or '(none)'}\n"
        f"Expires   : {expires_at}\n\n"
        f"Files\n-----\n"
        f"  {base_name}.ps1  Windows PowerShell 5.1+  (run as Administrator)\n"
        f"  {base_name}.sh   Linux / macOS bash        (run as root)\n\n"
        f"How it works\n------------\n"
        f"  1. Downloads the pre-configured collector package from S3\n"
        f"  2. Extracts and runs fo-harvester.py\n"
        f"  3. fo-harvester.py collects artifacts and uploads evidence to S3\n"
        f"  4. Deletes local temp files\n"
        f"  5. Deletes the collector package from S3\n\n"
        f"Usage\n-----\n"
        f"  Windows (run as Administrator):\n"
        f"      powershell -ExecutionPolicy Bypass -File {base_name}.ps1\n\n"
        f"  Linux / macOS (run as root):\n"
        f"      chmod +x {base_name}.sh && sudo ./{base_name}.sh\n\n"
        f"Flags\n-----\n"
        f"  --local        Save collected ZIP locally instead of uploading.\n"
        f"  --no-s3-del    (SH) Skip deleting collector zip from S3.\n"
        f"  -NoS3Cleanup   (PS1) Skip deleting collector zip from S3.\n"
        f"  -NoCleanup     (PS1) Keep local temp directory for debugging.\n\n"
        f"Security\n--------\n"
        f"  The collector URL is a time-limited presigned GET — it cannot list,\n"
        f"  write, or delete any other objects in the bucket.\n"
        f"  The DELETE URL removes only the collector package, not evidence.\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr(f"{base_name}.ps1", _fill(_BOOTSTRAP_PS1))
        zf.writestr(f"{base_name}.sh", _fill(_BOOTSTRAP_SH))
        zf.writestr("README.txt", readme.encode("utf-8"))
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{base_name}.zip"',
            "Cache-Control": "no-store",
        },
    )


# ── All-in-one bundle (collect + upload in one PS1 / SH script) ──────────────

_BUNDLE_PS1 = """#Requires -Version 5.1
<#
.SYNOPSIS
    ForensicsOperator - All-in-one collection and evidence upload bundle.
    Generated : TPLGENERATED_AT
    Expires   : TPLEXPIRES_AT
    Case      : TPLCASE_NAME
.DESCRIPTION
    Extracts fo-harvester.py, collects forensic artifacts, then uploads them
    via a pre-signed URL (no S3 credentials embedded).
    With -Local flag: saves the ZIP locally instead of uploading.
    Run as Administrator for complete collection.
.PARAMETER Local
    Save ZIP locally instead of uploading to S3.
.PARAMETER NoCleanup
    Keep temp directory after completion (useful for debugging).
.PARAMETER OutputDir
    Override the artifact output directory.
#>
param(
    [switch]$Local,
    [switch]$NoCleanup,
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"

# ── Configuration ──────────────────────────────────────────────────────────────
$PRESIGNED_URL = "TPLPRESIGNED_URL"
$EXPIRES_AT    = "TPLEXPIRES_AT"
$CASE_NAME     = "TPLCASE_NAME"

# ── Embedded fo-harvester.py (base64) ─────────────────────────────────────────
$HARVESTER_B64 = @'
TPLHARVESTER_B64
'@

# ── Collection config (config.json) ───────────────────────────────────────────
$CONFIG_JSON = @'
TPLCONFIG_JSON
'@

# ── Banner ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "  ForensicsOperator - Collection + Upload Bundle"             -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
if ($CASE_NAME)  { Write-Host "  Case    : $CASE_NAME"  }
if ($EXPIRES_AT) { Write-Host "  Expires : $EXPIRES_AT" }
Write-Host ""

# ── Check for Python 3 ────────────────────────────────────────────────────────
$python = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ("$ver" -match "Python 3") { $python = $cmd; break }
    } catch {}
}
if (-not $python) {
    Write-Host "ERROR: Python 3 not found. Install from https://python.org" -ForegroundColor Red
    exit 1
}
Write-Host "  Python : $(& $python --version 2>&1)" -ForegroundColor Green

# ── Create temp working directory ─────────────────────────────────────────────
$tmpDir = Join-Path $env:TEMP ("fo-bundle-" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

if ($OutputDir) {
    $outDir = $OutputDir
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
} else {
    $outDir = Join-Path $tmpDir "output"
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

# ── Write fo-harvester.py ─────────────────────────────────────────────────────
$harvesterPath = Join-Path $tmpDir "fo-harvester.py"
$b64Clean      = ($HARVESTER_B64 -replace "\\s+", "")
[System.IO.File]::WriteAllBytes($harvesterPath, [Convert]::FromBase64String($b64Clean))

# ── Write config.json ─────────────────────────────────────────────────────────
$configPath = Join-Path $tmpDir "config.json"
[System.IO.File]::WriteAllText($configPath, $CONFIG_JSON, [System.Text.Encoding]::UTF8)

# ── Run collection ─────────────────────────────────────────────────────────────
Write-Host "  Running collection..." -ForegroundColor Yellow
$prevDir = Get-Location
Set-Location $tmpDir
try {
    & $python fo-harvester.py --output $outDir
    if ($LASTEXITCODE -ne 0) { throw "fo-harvester.py exited with code $LASTEXITCODE" }
} finally {
    Set-Location $prevDir
}
Write-Host "  Collection complete." -ForegroundColor Green

# ── Find output ZIP ───────────────────────────────────────────────────────────
$zip = Get-ChildItem $outDir -Filter "fo-artifacts-*.zip" -ErrorAction SilentlyContinue |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $zip) {
    $zip = Get-ChildItem $outDir -Filter "*.zip" -ErrorAction SilentlyContinue |
           Sort-Object LastWriteTime -Descending | Select-Object -First 1
}
if (-not $zip) { throw "No output ZIP found in $outDir. Collection may have failed." }

# ── SHA-256 chain of custody ──────────────────────────────────────────────────
$hash  = (Get-FileHash $zip.FullName -Algorithm SHA256).Hash.ToLower()
$sizeMB = [math]::Round($zip.Length / 1MB, 1)
Write-Host ""
Write-Host "  Chain of custody:" -ForegroundColor Cyan
Write-Host "    File   : $($zip.Name)"
Write-Host "    Size   : ${sizeMB} MB"
Write-Host "    SHA-256: $hash"

# ── Upload or save locally ────────────────────────────────────────────────────
if ($PRESIGNED_URL -and -not $Local) {
    Write-Host ""
    Write-Host "  Uploading to evidence storage..." -ForegroundColor Yellow
    try {
        $fileStream = [System.IO.File]::OpenRead($zip.FullName)
        $client     = New-Object System.Net.Http.HttpClient
        $client.Timeout = [TimeSpan]::FromMinutes(30)
        $content    = New-Object System.Net.Http.StreamContent($fileStream)
        $content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/zip")
        $response   = $client.PutAsync($PRESIGNED_URL, $content).GetAwaiter().GetResult()
        $fileStream.Close()
        $code = [int]$response.StatusCode
        if ($code -lt 200 -or $code -ge 300) { throw "Server returned HTTP $code" }
        Write-Host "  Upload complete. HTTP $code" -ForegroundColor Green
    } catch {
        Write-Host "  Upload failed: $_  -- saving locally instead." -ForegroundColor Red
        $Local = $true
    }
} elseif (-not $PRESIGNED_URL) {
    Write-Host "  No upload URL configured -- saving locally." -ForegroundColor Yellow
    $Local = $true
}

if ($Local) {
    $dest = ".\\fo-artifacts-$env:COMPUTERNAME-$(Get-Date -Format 'yyyy-MM-dd')-Windows.zip"
    Copy-Item $zip.FullName $dest -Force
    Write-Host "  Saved locally: $(Resolve-Path $dest)" -ForegroundColor Green
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
if (-not $NoCleanup) {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Chain of custody hash (record this):"
Write-Host "  SHA-256: $hash" -ForegroundColor Cyan
Write-Host ""
Write-Host "=============================================================" -ForegroundColor Cyan
if ($PRESIGNED_URL -and -not $Local) {
    Write-Host "  Done. Open ForensicsOperator -> S3 Triage to import into a case." -ForegroundColor Cyan
} else {
    Write-Host "  Done. Upload the ZIP via ForensicsOperator -> Case -> Ingest." -ForegroundColor Cyan
}
Write-Host "=============================================================" -ForegroundColor Cyan
"""

_BUNDLE_SH = r"""#!/usr/bin/env bash
# ForensicsOperator - All-in-one collection and evidence upload bundle
# Generated : TPLGENERATED_AT
# Expires   : TPLEXPIRES_AT
# Case      : TPLCASE_NAME
#
# Usage:
#   sudo ./fo-bundle.sh           -- collect + upload to S3
#   sudo ./fo-bundle.sh --local   -- collect + save locally
#
# Requires: Python 3.6+, curl (for S3 upload)

set -euo pipefail

PRESIGNED_URL="TPLPRESIGNED_URL"
EXPIRES_AT="TPLEXPIRES_AT"
CASE_NAME="TPLCASE_NAME"
LOCAL=0

for arg in "$@"; do case "$arg" in --local) LOCAL=1 ;; esac; done

# ── Embedded fo-harvester.py ───────────────────────────────────────────────────
HARVESTER_B64=$(cat << 'ENDHARVESTER'
TPLHARVESTER_B64
ENDHARVESTER
)

# ── Collection config ──────────────────────────────────────────────────────────
CONFIG_JSON=$(cat << 'ENDCONFIG'
TPLCONFIG_JSON
ENDCONFIG
)

# ── Banner ─────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================="
echo "  ForensicsOperator - Collection + Upload Bundle"
echo "============================================================="
[ -n "$CASE_NAME"  ] && echo "  Case    : $CASE_NAME"
[ -n "$EXPIRES_AT" ] && echo "  Expires : $EXPIRES_AT"
echo ""

# ── Python check ───────────────────────────────────────────────────────────────
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" >/dev/null 2>&1; then
        pyver=$("$cmd" --version 2>&1 || true)
        case "$pyver" in "Python 3"*) PYTHON="$cmd"; break ;; esac
    fi
done
if [ -z "$PYTHON" ]; then
    echo "ERROR: Python 3 not found." >&2; exit 1
fi
echo "  Python : $($PYTHON --version 2>&1)"

# ── Temp directory ─────────────────────────────────────────────────────────────
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
OUTDIR="$WORKDIR/output"
mkdir -p "$OUTDIR"

# ── Extract harvester + write config ──────────────────────────────────────────
printf '%s' "$HARVESTER_B64" | base64 -d > "$WORKDIR/fo-harvester.py"
printf '%s' "$CONFIG_JSON"        > "$WORKDIR/config.json"

# ── Run collection ─────────────────────────────────────────────────────────────
echo "  Running collection..."
(cd "$WORKDIR" && "$PYTHON" fo-harvester.py --output "$OUTDIR")
echo "  Collection complete."

# ── Find output ZIP ────────────────────────────────────────────────────────────
ZIP=$(find "$OUTDIR" -name "fo-artifacts-*.zip" 2>/dev/null | sort | tail -1 || true)
[ -z "$ZIP" ] && ZIP=$(find "$OUTDIR" -name "*.zip" 2>/dev/null | sort | tail -1 || true)
if [ -z "$ZIP" ]; then
    echo "ERROR: No output ZIP found. Collection may have failed." >&2; exit 1
fi

# ── SHA-256 ────────────────────────────────────────────────────────────────────
if command -v sha256sum >/dev/null 2>&1; then
    HASH=$(sha256sum "$ZIP" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    HASH=$(shasum -a 256 "$ZIP" | awk '{print $1}')
else
    HASH="(sha256sum unavailable)"
fi
echo ""
echo "  Chain of custody:"
echo "    File   : $(basename "$ZIP")"
echo "    SHA-256: $HASH"

# ── Upload or save locally ─────────────────────────────────────────────────────
if [ -n "$PRESIGNED_URL" ] && [ "$LOCAL" -eq 0 ]; then
    echo ""
    echo "  Uploading to evidence storage..."
    if command -v curl >/dev/null 2>&1; then
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            -T "$ZIP" -H "Content-Type: application/zip" "$PRESIGNED_URL")
        if echo "$HTTP_CODE" | grep -qE "^2"; then
            echo "  Upload complete. HTTP $HTTP_CODE"
        else
            echo "  WARNING: Upload failed (HTTP $HTTP_CODE). Saving locally." >&2
            LOCAL=1
        fi
    else
        echo "  WARNING: curl not found. Saving locally." >&2
        LOCAL=1
    fi
elif [ -z "$PRESIGNED_URL" ]; then
    echo "  No upload URL -- saving locally."
    LOCAL=1
fi

if [ "$LOCAL" -eq 1 ]; then
    OS_TYPE=$(uname -s | sed 's/Darwin/macOS/')
    DEST="./fo-artifacts-$(hostname -s)-$(date +%Y-%m-%d)-${OS_TYPE}.zip"
    cp "$ZIP" "$DEST"
    echo "  Saved locally: $DEST"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "  Chain of custody hash (record this):"
echo "  SHA-256: $HASH"
echo ""
echo "============================================================="
if [ -n "$PRESIGNED_URL" ] && [ "$LOCAL" -eq 0 ]; then
    echo "  Done. Open ForensicsOperator -> S3 Triage to import into a case."
else
    echo "  Done. Upload the ZIP via ForensicsOperator -> Case -> Ingest."
fi
echo "============================================================="
"""


@router.get("/collector/bundle", dependencies=[Depends(require_analyst_or_admin)])
def download_bundle(
    categories: str | None = Query(
        default=None, description="Comma-separated artifact categories. All enabled if omitted."
    ),
    expires_hours: int = Query(default=24, description="Presigned URL validity (1–168 h)"),
    platform: str = Query(default="zip", description="ps1 | sh | zip (both)"),
    case_name: str | None = Query(default=None),
):
    """
    Return a self-contained collection + upload script (PS1, SH, or both in a ZIP).

    The script embeds fo-harvester.py as base64, a pre-generated presigned PUT URL
    for the S3 triage bucket, and the artifact selection config. The field operator
    runs ONE file — no credentials, no extra downloads.

    With --local flag the script saves the ZIP on disk instead of uploading.
    If no S3 triage config is saved, the presigned URL is omitted and the script
    automatically falls back to local save.
    """
    import base64 as _b64
    import json as _jsn
    import re as _re
    from datetime import datetime, timedelta

    platform = platform.lower()
    if platform not in ("ps1", "sh", "zip"):
        raise HTTPException(status_code=400, detail="platform must be ps1, sh, or zip")

    try:
        harvester_bytes = _find_collect_script().read_bytes()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    raw_b64 = _b64.b64encode(harvester_bytes).decode("ascii")
    harvester_b64 = "\n".join(raw_b64[i : i + 76] for i in range(0, len(raw_b64), 76))

    enabled = (
        [c.strip() for c in categories.split(",") if c.strip()]
        if categories
        else sorted(_valid_category_keys())  # all categories Talon advertises
    )
    cfg: dict = {
        "collect": enabled,
        "output_dir": "./output",
    }
    if case_name:
        cfg["case_name"] = case_name.strip()
    config_json = _jsn.dumps(cfg, indent=2)

    presigned_url = ""
    expires_at = ""
    try:
        from config import get_redis as _get_redis

        r = _get_redis()
        raw = r.get(rk.S3_TRIAGE_CONFIG)
        if raw:
            s3cfg = _jsn.loads(raw)
            if s3cfg.get("endpoint") and s3cfg.get("access_key") and s3cfg.get("secret_key"):
                mc = _triage_minio(s3cfg)
                now = datetime.now(UTC)
                ts = now.strftime("%Y%m%d-%H%M%S")
                safe_cn = _re.sub(r"[^\w.\-]", "_", case_name or "fo-artifacts")[:60]
                key = f"uploads/{ts}-{safe_cn}.zip"
                exp = timedelta(hours=max(1, min(expires_hours, 168)))
                presigned_url = mc.presigned_put_object(s3cfg["bucket"], key, expires=exp)
                expires_at = (now + exp).isoformat()
    except Exception as exc:
        logger.warning("Could not generate presigned URL for bundle: %s", exc)

    now_str = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    cn = case_name or ""

    def _ps1() -> bytes:
        return (
            _BUNDLE_PS1.replace("TPLGENERATED_AT", now_str)
            .replace("TPLEXPIRES_AT", expires_at)
            .replace("TPLCASE_NAME", cn)
            .replace("TPLPRESIGNED_URL", presigned_url)
            .replace("TPLHARVESTER_B64", harvester_b64)
            .replace("TPLCONFIG_JSON", config_json)
        ).encode("utf-8")

    def _sh() -> bytes:
        return (
            _BUNDLE_SH.replace("TPLGENERATED_AT", now_str)
            .replace("TPLEXPIRES_AT", expires_at)
            .replace("TPLCASE_NAME", cn)
            .replace("TPLPRESIGNED_URL", presigned_url)
            .replace("TPLHARVESTER_B64", harvester_b64)
            .replace("TPLCONFIG_JSON", config_json)
        ).encode("utf-8")

    safe_cn = _re.sub(r"[^\w\-]", "_", cn)[:30]
    ts_short = datetime.now(UTC).strftime("%Y%m%d")
    base_name = f"fo-bundle-{safe_cn}-{ts_short}" if safe_cn else f"fo-bundle-{ts_short}"

    if platform == "ps1":
        return Response(
            content=_ps1(),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{base_name}.ps1"',
                "Cache-Control": "no-store",
            },
        )
    if platform == "sh":
        return Response(
            content=_sh(),
            media_type="application/x-sh",
            headers={
                "Content-Disposition": f'attachment; filename="{base_name}.sh"',
                "Cache-Control": "no-store",
            },
        )

    readme = (
        f"ForensicsOperator Collection Bundle\n"
        f"Generated : {now_str}\n"
        f"Case      : {cn or '(none)'}\n"
        f"Expires   : {expires_at or 'no upload URL — local save only'}\n\n"
        f"Files\n-----\n"
        f"  {base_name}.ps1  Windows PowerShell 5.1+  (run as Administrator)\n"
        f"  {base_name}.sh   Linux / macOS bash        (run as root)\n\n"
        f"Usage\n-----\n"
        f"  Windows:\n"
        f"      powershell -ExecutionPolicy Bypass -File {base_name}.ps1\n\n"
        f"  Linux / macOS:\n"
        f"      chmod +x {base_name}.sh && sudo ./{base_name}.sh\n\n"
        f"Flags\n-----\n"
        f"  --local        Save ZIP locally instead of uploading to S3.\n"
        f"  -NoCleanup     (PS1 only) Keep temp directory for debugging.\n"
        f"  -OutputDir     (PS1 only) Override artifact output directory.\n\n"
        f"Chain of Custody\n----------------\n"
        f"  Both scripts print a SHA-256 hash before upload.\n"
        f"  Record this hash — it proves the file was not altered after collection.\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr(f"{base_name}.ps1", _ps1())
        zf.writestr(f"{base_name}.sh", _sh())
        zf.writestr("README.txt", readme.encode("utf-8"))
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{base_name}.zip"',
            "Cache-Control": "no-store",
        },
    )


# ── Network interface discovery ───────────────────────────────────────────────

_API_PORT = os.getenv("FO_PUBLIC_PORT", "8000")


def _parse_ip_addr() -> list[dict]:
    """Parse `ip addr show` to get all non-loopback IPv4 interface addresses."""
    results = []
    try:
        out = subprocess.check_output(["ip", "addr", "show"], text=True, timeout=5)
        iface = ""
        for line in out.splitlines():
            line = line.strip()
            if line and line[0].isdigit():
                # "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
                iface = line.split(":")[1].strip().split("@")[0]
            elif line.startswith("inet ") and "127." not in line:
                # "inet 192.168.1.100/24 brd ..."
                ip = line.split()[1].split("/")[0]
                results.append({"ip": ip, "iface": iface})
    except (OSError, subprocess.SubprocessError) as exc:
        # Best-effort probe — `ip` may be absent (non-Linux); other detectors cover it
        logger.debug("ip addr probe failed: %s", exc)
    return results


def _detect_gateway_ip() -> str | None:
    """Default gateway — on Docker bridge networks this is the host machine's docker bridge IP."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True,
            timeout=3,
        )
        parts = out.split()
        idx = parts.index("via") if "via" in parts else -1
        if idx >= 0 and idx + 1 < len(parts):
            return parts[idx + 1]
    except (OSError, subprocess.SubprocessError) as exc:
        # Best-effort probe — no default route / no `ip` binary is a normal case
        logger.debug("default gateway probe failed: %s", exc)
    return None


def _detect_outbound_ip() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError as exc:
        # Best-effort probe — offline hosts have no outbound route
        logger.debug("outbound IP probe failed: %s", exc)
        return None


def _resolve_host_docker_internal() -> str | None:
    """
    Resolve host.docker.internal — set automatically by Docker Desktop on Mac/Windows.

    On Linux Docker with bridge networking this hostname may not be set unless
    '--add-host=host-gateway' is in the run flags. Returns None if not resolvable.
    """
    try:
        addr = socket.gethostbyname("host.docker.internal")
        if addr and not addr.startswith("127."):
            return addr
    except (socket.gaierror, OSError):
        pass
    # Also scan /etc/hosts for Docker-injected entries
    try:
        for line in Path("/etc/hosts").read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "host.docker.internal" in line or "host-gateway" in line:
                parts = line.split()
                if parts and not parts[0].startswith("127."):
                    return parts[0]
    except OSError as exc:
        # Best-effort probe — /etc/hosts may be unreadable in hardened containers
        logger.debug("/etc/hosts scan failed: %s", exc)
    return None


def _ip_label(ip: str) -> str:
    """Return a human-readable label for an IP based on its range."""
    if ip.startswith("172."):
        return "docker bridge"
    if ip.startswith("192.168."):
        return "LAN"
    if ip.startswith("10."):
        return "private network"
    if ip.startswith("169.254."):
        return "link-local"
    return "interface"


def _only_docker_ips(candidates: list[dict]) -> bool:
    """Return True if all detected IPs (excluding FO_PUBLIC_URL) are Docker-internal."""
    non_config = [c for c in candidates if c.get("iface") != "FO_PUBLIC_URL"]
    if not non_config:
        return False
    return all(
        c["ip"].startswith("172.") or c["ip"].startswith("10.")
        for c in non_config
        if not c.get("k8s")
    )


def _is_kubernetes() -> bool:
    """Return True when running inside a Kubernetes pod (service account is mounted)."""
    return os.path.isfile("/var/run/secrets/kubernetes.io/serviceaccount/token")


# ── Kubernetes LoadBalancer service settings (used by helpers + endpoints) ────

_LB_SVC_NAME = os.getenv("FO_LB_SERVICE_NAME", "fo-collector-lb")
_LB_NAMESPACE = os.getenv("FO_NAMESPACE", "default")
_LB_TARGET_PORT = int(os.getenv("FO_API_PORT", "8000"))
_LB_APP_LABEL = os.getenv("FO_APP_LABEL", "fo-api")


# ── Kubernetes in-cluster API helpers ─────────────────────────────────────────

_K8S_HOST = "https://kubernetes.default.svc"
_K8S_TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
_K8S_CA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
_K8S_NS_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")


def _k8s_namespace() -> str:
    """Read the pod's namespace from the mounted service account files."""
    try:
        return _K8S_NS_PATH.read_text().strip() or _LB_NAMESPACE
    except OSError:
        return _LB_NAMESPACE  # not in a pod / file not mounted — fall back to env default


def _k8s_request(
    method: str,
    path: str,
    body: dict | None = None,
) -> tuple[int, dict]:
    """
    Make an authenticated request to the Kubernetes API server using the
    in-cluster service account token.  No kubectl needed.
    Returns (http_status_code, parsed_json_response).
    """
    try:
        token = _K8S_TOKEN_PATH.read_text().strip()
    except OSError as exc:
        logger.error("Cannot read K8s service account token: %s", exc)
        return 0, {"error": "cannot read service account token"}

    url = f"{_K8S_HOST}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")

    ssl_ctx = ssl.create_default_context()
    if _K8S_CA_PATH.is_file():
        ssl_ctx.load_verify_locations(str(_K8S_CA_PATH))
    else:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        # HTTP-level error — the API server answered; preserve its status code
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except ValueError:  # non-JSON error body (covers JSONDecodeError + bad encoding)
            return exc.code, {"message": raw.decode(errors="replace")[:500]}
    except urllib.error.URLError as exc:
        # Transport-level error — API server unreachable (DNS, TLS, refused, timeout)
        logger.error("K8s API unreachable [%s %s]: %s", method, path, exc.reason)
        return 0, {"error": str(exc)}
    except (OSError, json.JSONDecodeError) as exc:
        # I/O failure mid-read or a 200 response with a malformed body
        logger.error("K8s API request failed [%s %s]: %s", method, path, exc)
        return 0, {"error": str(exc)}


def _get_k8s_service_ips() -> list[dict]:
    """Query the K8s API for LoadBalancer / NodePort services and return their IPs."""
    status, data = _k8s_request("GET", "/api/v1/services")
    if status != 200:
        return []
    results = []
    for item in data.get("items", []):
        svc_name = item.get("metadata", {}).get("name", "")
        ns = item.get("metadata", {}).get("namespace", "default")
        svc_type = item.get("spec", {}).get("type", "")
        # LoadBalancer external IPs
        for ing in item.get("status", {}).get("loadBalancer", {}).get("ingress", []):
            addr = ing.get("ip") or ing.get("hostname")
            if addr:
                results.append(
                    {
                        "ip": addr,
                        "iface": f"k8s/{ns}/{svc_name}",
                        "label": f"LoadBalancer ({svc_name})",
                        "k8s": True,
                    }
                )
        # NodePort — include cluster IP as a reachable candidate
        if svc_type == "NodePort":
            cluster_ip = item.get("spec", {}).get("clusterIP", "")
            if cluster_ip and cluster_ip != "None":
                results.append(
                    {
                        "ip": cluster_ip,
                        "iface": f"k8s/{ns}/{svc_name}",
                        "label": f"NodePort ({svc_name})",
                        "k8s": True,
                    }
                )
    return results


@router.get("/network/interfaces")
def get_network_interfaces():
    """
    Return candidate API endpoint URLs ordered by usefulness.
    The frontend renders them as one-click chips in the collector config step.
    """
    candidates: list[dict] = []
    seen: set[str] = set()

    def _add(ip: str, label: str, iface: str = "", k8s: bool = False) -> None:
        if ip and ip not in seen and not ip.startswith("127."):
            seen.add(ip)
            candidates.append(
                {
                    "ip": ip,
                    "url": f"http://{ip}:{_API_PORT}/api/v1",
                    "label": label,
                    "iface": iface,
                    "k8s": k8s,
                }
            )

    # 1. Operator-configured public URL (highest priority)
    public_url = os.getenv("FO_PUBLIC_URL", "").strip().rstrip("/")
    if public_url:
        host = public_url.split("//")[-1].split("/")[0].split(":")[0]
        url = public_url if "/api/v1" in public_url else f"{public_url}/api/v1"
        candidates.append(
            {"ip": host, "url": url, "label": "configured", "iface": "FO_PUBLIC_URL", "k8s": False}
        )
        seen.add(host)

    # 2. Kubernetes LoadBalancer / NodePort services
    if _is_kubernetes():
        for entry in _get_k8s_service_ips():
            _add(entry["ip"], entry["label"], entry["iface"], k8s=True)

    # 3. host.docker.internal — Docker Desktop Mac/Windows injects the host IP here
    host_docker = _resolve_host_docker_internal()
    if host_docker:
        _add(host_docker, "host machine (Docker Desktop)", "host.docker.internal")

    # 4. All non-loopback interface IPs (from ip addr)
    for entry in _parse_ip_addr():
        _add(entry["ip"], _ip_label(entry["ip"]), entry["iface"])

    # 5. Default gateway (Docker bridge host on Linux Docker)
    gw = _detect_gateway_ip()
    if gw:
        # Only show the gateway if it's not already in the list
        _add(gw, "docker host (gateway)", "gateway")

    # 6. Outbound socket IP (last resort)
    _add(_detect_outbound_ip(), "outbound", "socket")

    # Attach a helper flag so the frontend can show a "set FO_PUBLIC_URL" tip
    only_internal = _only_docker_ips(candidates)

    return {
        "candidates": candidates,
        "port": int(_API_PORT),
        "in_kubernetes": _is_kubernetes(),
        "only_docker_ips": only_internal,
        "public_url_hint": (
            "No external IP detected. Set FO_PUBLIC_URL=http://<your-lan-ip>:8000 "
            "in docker-compose.yml for collectors to reach this server."
            if only_internal and not _is_kubernetes()
            else None
        ),
    }


# ── Kubernetes LoadBalancer ingress management ────────────────────────────────
# The pod's service account needs the following RBAC permissions.
# Apply once to your cluster before using these endpoints:
#
#   kubectl apply -f - <<'EOF'
#   apiVersion: rbac.authorization.k8s.io/v1
#   kind: Role
#   metadata:
#     name: fo-service-manager
#     namespace: <your-namespace>
#   rules:
#   - apiGroups: [""]
#     resources: ["services"]
#     verbs: ["get", "list", "create", "delete"]
#   ---
#   apiVersion: rbac.authorization.k8s.io/v1
#   kind: RoleBinding
#   metadata:
#     name: fo-service-manager
#     namespace: <your-namespace>
#   subjects:
#   - kind: ServiceAccount
#     name: default          # or your custom SA name
#     namespace: <your-namespace>
#   roleRef:
#     kind: Role
#     name: fo-service-manager
#     apiGroup: rbac.authorization.k8s.io
#   EOF


def _build_lb_manifest(namespace: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": _LB_SVC_NAME,
            "namespace": namespace,
            "labels": {"managed-by": "forensicsoperator"},
        },
        "spec": {
            "type": "LoadBalancer",
            "selector": {"app": _LB_APP_LABEL},
            "ports": [{"port": _LB_TARGET_PORT, "targetPort": _LB_TARGET_PORT, "protocol": "TCP"}],
        },
    }


@router.post("/collector/ingress", status_code=201)
def create_collector_ingress():
    """
    Create a Kubernetes LoadBalancer Service that exposes the API externally
    so remote collectors can upload artifacts.
    Uses the pod's in-cluster service account — no kubectl required.
    The service account needs RBAC: create/get/delete on services in its namespace.
    """
    if not _is_kubernetes():
        raise HTTPException(
            status_code=400,
            detail="Not running in Kubernetes — use the FO_PUBLIC_URL env var to set the external URL manually.",
        )
    ns = _k8s_namespace()
    manifest = _build_lb_manifest(ns)
    status, body = _k8s_request("POST", f"/api/v1/namespaces/{ns}/services", body=manifest)

    if status == 409:
        # Service already exists — return current status
        logger.info("LoadBalancer service %s already exists", _LB_SVC_NAME)
    elif status not in (200, 201):
        msg = body.get("message", str(body))[:300]
        logger.error("K8s API error creating service (%d): %s", status, msg)
        raise HTTPException(status_code=500, detail=f"Kubernetes API error ({status}): {msg}")

    return _get_lb_status()


@router.get("/collector/ingress")
def get_collector_ingress():
    """Query the status and external IP of the collector LoadBalancer service."""
    if not _is_kubernetes():
        raise HTTPException(status_code=400, detail="Not running in Kubernetes.")
    return _get_lb_status()


@router.get("/collector/ingress/rbac")
def get_ingress_rbac():
    """
    Return a ready-to-apply RBAC Role + RoleBinding manifest that grants the
    pod's default service account permission to create/get/delete Services.
    Apply once: kubectl apply -f <(curl -s .../collector/ingress/rbac)
    """
    ns = _k8s_namespace() if _is_kubernetes() else _LB_NAMESPACE
    manifest = f"""apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: fo-service-manager
  namespace: {ns}
rules:
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list", "create", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: fo-service-manager
  namespace: {ns}
subjects:
- kind: ServiceAccount
  name: default
  namespace: {ns}
roleRef:
  kind: Role
  name: fo-service-manager
  apiGroup: rbac.authorization.k8s.io
"""
    return Response(
        content=manifest,
        media_type="text/yaml",
        headers={"Content-Disposition": 'attachment; filename="fo-rbac.yaml"'},
    )


@router.delete("/collector/ingress", status_code=204)
def delete_collector_ingress():
    """Remove the collector LoadBalancer service."""
    if not _is_kubernetes():
        raise HTTPException(status_code=400, detail="Not running in Kubernetes.")
    ns = _k8s_namespace()
    status, body = _k8s_request(
        "DELETE",
        f"/api/v1/namespaces/{ns}/services/{_LB_SVC_NAME}",
    )
    if status not in (200, 202, 404):
        msg = body.get("message", str(body))[:300]
        raise HTTPException(status_code=500, detail=f"Kubernetes API error ({status}): {msg}")


def _get_lb_status() -> dict:
    ns = _k8s_namespace()
    status, data = _k8s_request(
        "GET",
        f"/api/v1/namespaces/{ns}/services/{_LB_SVC_NAME}",
    )
    if status == 404:
        return {
            "name": _LB_SVC_NAME,
            "status": "not_found",
            "external_ip": None,
            "external_url": None,
        }
    if status != 200:
        return {
            "name": _LB_SVC_NAME,
            "status": "error",
            "external_ip": None,
            "external_url": None,
            "error": data.get("message", "")[:200],
        }
    ingresses = data.get("status", {}).get("loadBalancer", {}).get("ingress", [])
    ip = ingresses[0].get("ip") if ingresses else None
    host = ingresses[0].get("hostname") if ingresses else None
    addr = ip or host
    return {
        "name": _LB_SVC_NAME,
        "namespace": ns,
        "status": "ready" if addr else "pending",
        "external_ip": addr,
        "external_url": f"http://{addr}:{_LB_TARGET_PORT}/api/v1" if addr else None,
    }
