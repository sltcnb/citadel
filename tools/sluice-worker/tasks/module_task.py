"""
Module execution task: download source files, run module binary, store results.

Supported modules:
  hayabusa         — Sigma-based EVTX threat hunting
  strings          — Printable string extraction from any file
  strings_analysis — Categorised string extraction with IOC identification
  hindsight        — Browser forensics (Chrome/Firefox/Edge)
  regripper        — Deep Windows registry analysis
  wintriage        — Windows triage collection analysis
  yara             — YARA rule scanning
  exiftool         — Metadata extraction
  volatility3      — Memory forensics
  oletools         — Office document macro / OLE analysis
  ole_analysis     — Alias for oletools
  pe_analysis      — PE executable deep inspection
  grep_search      — Regex-based IOC / keyword pattern search
  malwoverview     — VirusTotal / multi-TI hash lookup (malwoverview CLI or direct API)
"""

from __future__ import annotations

import csv
import importlib.util
import json
import logging
import os
import re
import shutil
import struct
import subprocess
import sys
import sysconfig
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path

import redis
import redis_keys as rk
from celery_app import app

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis-service:6379/0")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio-service:9000")
MINIO_ACCESS = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "forensics-cases")
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch-service:9200")

# Custom modules directory (shared volume, created via Studio UI)
CUSTOM_MODULES_DIR = Path(os.getenv("MODULES_DIR", "/app/anvil"))

MODULE_RUN_TTL = 604800  # 7 days

LEVEL_INT = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
}

# Strip ANSI terminal escape sequences before storing output in Redis / displaying in UI
_ANSI_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-9;]*[ -/]*[@-~])")

# Minimal subprocess environment — strips MINIO/Redis secrets from child processes
# so that a compromised binary cannot exfiltrate credentials via env inheritance.
_SAFE_ENV = {
    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
    "HOME": "/tmp",
    "LANG": os.environ.get("LANG", "en_US.UTF-8"),
    "TMPDIR": "/tmp",
}

# Redis key for UI-configured Cuckoo integration settings
_CUCKOO_CONFIG_KEY = rk.CUCKOO_CONFIG


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


_SANDBOX_SCRIPT = Path(__file__).parent / "_module_sandbox.py"

# Resource limits for custom module subprocess
_SANDBOX_CPU_SECONDS = int(os.getenv("SANDBOX_CPU_SECONDS", "3600"))
_SANDBOX_MEMORY_BYTES = int(os.getenv("SANDBOX_MEMORY_BYTES", str(2 * 1024**3)))
_SANDBOX_FSIZE_BYTES = int(os.getenv("SANDBOX_FSIZE_BYTES", str(500 * 1024**2)))
_SANDBOX_NPROC = int(os.getenv("SANDBOX_NPROC", "64"))
_SANDBOX_TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT_SEC", "1800"))  # 30 min wall time


def _read_module_constants(module_id: str) -> dict:
    """Read ARTIFACT_TYPE and INDEX_SKIP from a custom module file via text scan (no execution)."""
    module_file = CUSTOM_MODULES_DIR / f"{module_id}_module.py"
    if not module_file.exists():
        return {}
    try:
        import re as _re

        text = module_file.read_text()
        artifact_type = None
        index_skip = False
        for line in text.splitlines():
            line = line.strip()
            if m := _re.match(r'^ARTIFACT_TYPE\s*=\s*["\']([^"\']+)["\']', line):
                artifact_type = m.group(1)
            elif _re.match(r"^INDEX_SKIP\s*=\s*True", line):
                index_skip = True
        return {"artifact_type": artifact_type, "index_skip": index_skip}
    except Exception:
        return {}


def _run_custom_module(
    run_id: str,
    case_id: str,
    module_id: str,
    work_dir: Path,
    source_files: list,
    params: dict,
    tool_meta: dict,
) -> list[dict]:
    """
    Execute a custom *_module.py file in an isolated subprocess.

    The child process:
      • sets resource limits (CPU, memory, file size, nproc) before importing
        any module code — limits cascade to any subprocesses the module spawns
      • receives MinIO/Redis credentials via stdin (not visible in ps/env)
      • has HOME remapped to work_dir and sensitive env vars stripped
      • is killed by the parent after SANDBOX_TIMEOUT_SEC wall-clock seconds

    Returns the list of hit dicts produced by the module's run() function.
    """
    import sys as _sys

    module_file = CUSTOM_MODULES_DIR / f"{module_id}_module.py"
    if not module_file.exists():
        raise RuntimeError(
            f"Custom module file not found: {module_file}. Create it in the Studio editor."
        )

    args_payload = json.dumps(
        {
            "run_id": run_id,
            "case_id": case_id,
            "module_file": str(module_file),
            "source_files": source_files,
            "params": params,
            "work_dir": str(work_dir),
            "minio_endpoint": MINIO_ENDPOINT,
            "minio_access": MINIO_ACCESS,
            "minio_secret": MINIO_SECRET,
            "minio_bucket": MINIO_BUCKET,
            "redis_url": REDIS_URL,
            # Propagate limit overrides so sandbox can log them
            "limit_cpu_seconds": _SANDBOX_CPU_SECONDS,
            "limit_memory_bytes": _SANDBOX_MEMORY_BYTES,
            "limit_fsize_bytes": _SANDBOX_FSIZE_BYTES,
            "limit_nproc": _SANDBOX_NPROC,
        }
    )

    logger.info(
        "[%s] Launching custom module '%s' in sandbox (timeout=%ss)",
        run_id,
        module_id,
        _SANDBOX_TIMEOUT,
    )
    tool_meta["log"] += (
        f"[sandbox] executing {module_file.name} in subprocess "
        f"(cpu={_SANDBOX_CPU_SECONDS}s mem={_SANDBOX_MEMORY_BYTES // 1024**2}MB "
        f"fsize={_SANDBOX_FSIZE_BYTES // 1024**2}MB nproc={_SANDBOX_NPROC})\n"
    )

    try:
        proc = subprocess.run(
            [_sys.executable, str(_SANDBOX_SCRIPT)],
            input=args_payload,
            capture_output=True,
            text=True,
            timeout=_SANDBOX_TIMEOUT,
            # Inherit only a minimal environment — no secrets in child env
            env={
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
                "HOME": str(work_dir),
            },
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Custom module '{module_id}' timed out after {_SANDBOX_TIMEOUT}s")

    stderr_out = (proc.stderr or "").strip()
    if stderr_out:
        tool_meta["log"] += f"\n[sandbox stderr]\n{stderr_out[:8000]}\n"
        logger.info("[%s] Sandbox stderr:\n%s", run_id, stderr_out[:3000])

    stdout_out = (proc.stdout or "").strip()
    tool_meta["stdout"] = stdout_out[:4000] if stdout_out else ""

    if proc.returncode != 0:
        raise RuntimeError(
            f"Custom module '{module_id}' subprocess exited {proc.returncode}. "
            f"stderr: {stderr_out[:500]}"
        )

    try:
        result = json.loads(stdout_out)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Custom module '{module_id}' produced invalid JSON output: {exc}. "
            f"stdout: {stdout_out[:300]}"
        ) from exc

    if "error" in result:
        raise RuntimeError(f"Custom module '{module_id}' failed: {result['error']}")

    hits = result.get("hits", [])
    # Persist the structured Result envelope (artifacts/metrics/status) produced
    # by typed BaseModule analyzers — previously dropped. Stored on the module
    # run record so the API/UI can surface produced artifacts + run metrics.
    artifacts = result.get("artifacts") or []
    metrics = result.get("metrics") or {}
    if artifacts or metrics:
        try:
            r = get_redis()
            payload = {}
            if artifacts:
                payload["artifacts"] = json.dumps(artifacts)
            if metrics:
                payload["metrics"] = json.dumps(metrics)
            if result.get("status"):
                payload["module_status"] = result["status"]
            r.hset(rk.module_run(run_id), mapping=payload)
            logger.info("[%s] Custom module produced %d artifact(s)", run_id, len(artifacts))
        except Exception as exc:  # noqa: BLE001 - persistence is best-effort
            logger.warning("[%s] failed to persist module artifacts: %s", run_id, exc)
    logger.info("[%s] Custom module returned %d hits", run_id, len(hits))
    return hits


def get_redis() -> redis.Redis:
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def get_minio():
    from minio import Minio

    return Minio(MINIO_ENDPOINT, access_key=MINIO_ACCESS, secret_key=MINIO_SECRET, secure=False)


_CONN_ERRORS = (
    "connection refused",
    "max retries",
    "timeout",
    "connect",
    "reset by peer",
    "broken pipe",
    "connection reset",
    "econnrefused",
)


def _minio_op(fn, max_tries: int = 4, base_delay: float = 3.0):
    """Execute fn(), retrying on transient MinIO connectivity errors with exponential backoff."""
    last_exc = None
    for attempt in range(max_tries):
        try:
            return fn()
        except Exception as exc:
            msg = str(exc).lower()
            if any(k in msg for k in _CONN_ERRORS):
                last_exc = exc
                if attempt < max_tries - 1:
                    wait = base_delay * (2**attempt)
                    logger.warning(
                        "MinIO attempt %d/%d failed (%s). Retrying in %.0fs…",
                        attempt + 1,
                        max_tries,
                        exc,
                        wait,
                    )
                    time.sleep(wait)
                    continue
            raise
    raise last_exc  # type: ignore[misc]


def _update(r: redis.Redis, run_id: str, **fields) -> None:
    key = rk.module_run(run_id)
    r.hset(
        key,
        mapping={
            k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in fields.items()
        },
    )
    r.expire(key, MODULE_RUN_TTL)


_LOG_TTL = 86400  # 24 h — only needed while the UI is watching


def _push_log(r: redis.Redis, run_id: str, text: str) -> None:
    """Append a log line to the SSE list and logger simultaneously."""
    key = rk.module_log(run_id)
    r.rpush(key, text)
    r.expire(key, _LOG_TTL)
    logger.info("[%s] %s", run_id, text)


class _Cancelled(Exception):
    """Raised at a cancel checkpoint when the analyst cancelled the run."""


def _check_cancel(r: redis.Redis, run_id: str) -> None:
    """Co-operative cancel — the API sets a flag, we honour it at phase
    boundaries (queue pickup, between downloads, before indexing). A module
    binary already executing can't be interrupted mid-flight; the run is
    cancelled right after it returns instead."""
    if r.get(rk.module_cancel(run_id)):
        raise _Cancelled()


# ── Celery task ────────────────────────────────────────────────────────────────


@app.task(bind=True, name="module.run", queue="modules")
def run_module(
    self,
    run_id: str,
    case_id: str,
    module_id: str,
    source_files: list,
    params: dict | None = None,
) -> dict:
    """
    Execute a module against a set of source files already stored in MinIO.

    source_files: list of {job_id, filename, minio_key}
    params: optional module-specific parameters (e.g. custom YARA rules)
    """
    r = get_redis()
    work_dir = Path(tempfile.mkdtemp(prefix=f"fo_mod_{run_id}_"))
    params = params or {}

    try:
        _check_cancel(r, run_id)  # cancelled while still queued
        _update(r, run_id, status="RUNNING", started_at=datetime.now(UTC).isoformat())
        _push_log(r, run_id, f"Module '{module_id}' started — {len(source_files)} source file(s)")

        # ── 1. Download source files ──────────────────────────────────────────
        minio = get_minio()
        sources_dir = work_dir / "sources"
        sources_dir.mkdir()

        # ES-only modules scan Elasticsearch events directly — they never touch
        # the raw artifacts. Downloading every case file for them was needless
        # MinIO load (and the source of "too many 503 error responses" on big
        # cases). Skip staging for them.
        _ES_ONLY_MODULES = {"cti_match", "browser_report", "auth_summary"}
        if module_id in _ES_ONLY_MODULES:
            _push_log(r, run_id, f"Module '{module_id}' scans Elasticsearch — skipping source download")
        else:
            for sf in source_files:
                _check_cancel(r, run_id)
                dest = sources_dir / sf["filename"]
                _push_log(r, run_id, f"Downloading {sf['filename']} …")
                _minio_op(lambda d=dest, k=sf["minio_key"]: minio.fget_object(MINIO_BUCKET, k, str(d)))
                _push_log(r, run_id, f"Downloaded {sf['filename']} ({dest.stat().st_size:,} bytes)")

        _check_cancel(r, run_id)
        _push_log(r, run_id, f"Running module '{module_id}' …")

        # ── 2. Run module ─────────────────────────────────────────────────────
        # tool_meta captures subprocess output for display in the UI
        tool_meta: dict[str, str] = {"stdout": "", "stderr": "", "log": ""}

        # Built-in runners: complex modules that need direct process access or
        # have special ES indexers. All others are loaded from modules/*_module.py.
        RUNNERS = {
            "hayabusa": _run_hayabusa,
            "hindsight": _run_hindsight,
            "regripper": _run_regripper,
            "wintriage": _run_wintriage,
            "yara": _run_yara,
            "volatility3": _run_volatility3,
            "cuckoo": _run_cuckoo,
        }
        runner = RUNNERS.get(module_id)
        _mod_meta = {}  # populated for custom modules; holds ARTIFACT_TYPE / INDEX_SKIP

        _ES_RUNNERS = {
            "cti_match": _run_cti_match,
            "browser_report": _run_browser_report,
            "auth_summary": _run_auth_summary,
        }
        if module_id in _ES_RUNNERS:
            # Special runners: query ES events directly — uniform signature.
            results = _ES_RUNNERS[module_id](run_id, case_id, work_dir, sources_dir, params, tool_meta)
        elif runner is not None:
            # Built-in module — run directly in this process
            # Inject case_company so modules can apply company-scoped filtering (e.g. YARA)
            if "case_company" not in params:
                try:
                    _raw_co = get_redis().hget(f"case:{case_id}", "company")
                    params = {
                        **params,
                        "case_company": (
                            _raw_co.decode() if isinstance(_raw_co, bytes) else _raw_co
                        )
                        or "",
                    }
                except Exception:
                    pass
            results = runner(run_id, work_dir, sources_dir, params, tool_meta)
        else:
            # Custom module — run in isolated sandboxed subprocess
            _mod_meta = _read_module_constants(module_id)
            results = _run_custom_module(
                run_id, case_id, module_id, work_dir, source_files, params, tool_meta
            )

        # ── 3a. Upload module output artifacts (e.g. de4dot deobfuscated binaries) ────
        artifact_key_map: dict[str, str] = {}
        for spec in tool_meta.get("output_uploads", []):
            fpath = Path(spec.get("path", ""))
            if not fpath.is_file():
                continue
            art_key = f"cases/{case_id}/modules/{run_id}/artifacts/{spec['filename']}"
            try:
                _minio_op(lambda k=art_key, p=fpath: minio.fput_object(MINIO_BUCKET, k, str(p)))
                artifact_key_map[spec["filename"]] = art_key
                logger.info("[%s] Uploaded artifact: %s", run_id, spec["filename"])
            except Exception as _art_exc:
                logger.warning(
                    "[%s] Artifact upload failed for %s: %s", run_id, spec["filename"], _art_exc
                )

        # Patch results with download_key so the frontend can offer download
        if artifact_key_map:
            for hit in results:
                try:
                    det = json.loads(hit.get("details_raw", "{}"))
                    deob = det.get("deobfuscated")
                    if deob and deob in artifact_key_map:
                        det["download_key"] = artifact_key_map[deob]
                        det["download_name"] = deob
                        hit["details_raw"] = json.dumps(det)
                except Exception:
                    pass

        # Cancelled while the module binary was running — drop its output
        # rather than indexing results the analyst no longer wants.
        _check_cancel(r, run_id)

        # ── 3c. Index module hits into Elasticsearch so they appear in Timeline ──
        _index_at = datetime.now(UTC).isoformat()
        if results:
            try:
                if module_id == "hayabusa":
                    indexed = _hayabusa_index_to_es(case_id, run_id, results, _index_at)
                elif module_id == "browser_report":
                    indexed = _browser_report_index_to_es(case_id, run_id, results, _index_at)
                elif module_id not in _MODULE_INDEX_SKIP and not _mod_meta.get("index_skip", False):
                    indexed = _generic_module_index_to_es(
                        case_id, run_id, module_id, results, _index_at
                    )
                else:
                    indexed = 0
                if indexed:
                    atype = (
                        _mod_meta.get("artifact_type")
                        or _MODULE_ARTIFACT_TYPE.get(module_id)
                        or module_id.replace("-", "_").replace(" ", "_")
                    )
                    tool_meta["log"] += (
                        f"\nIndexed {indexed} events into Elasticsearch (artifact_type={atype})\n"
                    )
                    tool_meta["stdout"] += (
                        f"\n=== Indexed {indexed} events into Timeline (ES) ===\n"
                    )
            except Exception as _es_exc:
                logger.warning("[%s] ES indexing failed (non-fatal): %s", run_id, _es_exc)
                tool_meta["log"] += f"\n[ES index warning: {_es_exc}]\n"

        # ── 3. Upload full results to MinIO ───────────────────────────────────
        results_json = work_dir / "results.json"
        results_json.write_text(json.dumps(results, ensure_ascii=False))
        output_key = f"cases/{case_id}/modules/{run_id}/results.json"
        _minio_op(
            lambda: minio.fput_object(
                MINIO_BUCKET, output_key, str(results_json), content_type="application/json"
            )
        )
        logger.info("[%s] Uploaded %d hits to MinIO", run_id, len(results))

        # ── 4. Level summary ─────────────────────────────────────────────────
        hits_by_level: dict[str, int] = {}
        for hit in results:
            lvl = hit.get("level", "informational")
            hits_by_level[lvl] = hits_by_level.get(lvl, 0) + 1

        # ── 5. Complete ───────────────────────────────────────────────────────
        # Sort by severity descending for the preview so the most critical
        # detections always appear first — not just the first 200 by timestamp.
        results_by_severity = sorted(results, key=lambda h: h.get("level_int", 1), reverse=True)
        _update(
            r,
            run_id,
            status="COMPLETED",
            total_hits=str(len(results)),
            hits_by_level=json.dumps(hits_by_level),
            results_preview=json.dumps(results_by_severity[:200]),
            output_minio_key=output_key,
            tool_stdout=tool_meta.get("stdout", "")[:16000],
            tool_stderr=tool_meta.get("stderr", "")[:4000],
            tool_log=tool_meta.get("log", "")[:8000],
            completed_at=datetime.now(UTC).isoformat(),
        )

        _push_log(r, run_id, f"Completed — {len(results)} hit(s) found")
        logger.info("[%s] Module run complete: %d hits", run_id, len(results))

        # Notify subscribed webhooks — only when the module actually found
        # something; clean runs would be pure noise for an alert channel.
        if results:
            try:
                from tasks._webhooks import fire_webhooks

                raw_name = r.hget(f"case:{case_id}", "name")
                case_name = (
                    raw_name.decode() if isinstance(raw_name, bytes) else raw_name
                ) or case_id
                level_txt = ", ".join(
                    f"{n} {lvl}" for lvl, n in sorted(hits_by_level.items(), key=lambda kv: -kv[1])
                )
                fire_webhooks(
                    r,
                    "module_completed",
                    {
                        "event": "module_completed",
                        "text": (
                            f"Citadel: module '{module_id}' finished on case "
                            f"{case_name} — {len(results)} hit(s) ({level_txt})"
                        ),
                        "case_id": case_id,
                        "case_name": case_name,
                        "module_id": module_id,
                        "run_id": run_id,
                        "total_hits": len(results),
                        "hits_by_level": hits_by_level,
                    },
                )
            except Exception as _wh_exc:
                logger.warning("[%s] webhook notify failed: %s", run_id, _wh_exc)

        return {"status": "COMPLETED", "total_hits": len(results)}

    except _Cancelled:
        logger.info("[%s] Module run cancelled by analyst", run_id)
        _push_log(r, run_id, "Cancelled by analyst")
        _update(r, run_id, status="CANCELLED", completed_at=datetime.now(UTC).isoformat())
        r.delete(rk.module_cancel(run_id))
        return {"status": "CANCELLED", "total_hits": 0}

    except Exception as exc:
        logger.exception("[%s] Module run failed: %s", run_id, exc)
        _push_log(r, run_id, f"ERROR: {exc}")
        _update(
            r,
            run_id,
            status="FAILED",
            error=str(exc),
            tool_stdout=tool_meta.get("stdout", "")[:8000] if "tool_meta" in dir() else "",
            tool_stderr=tool_meta.get("stderr", "")[:4000] if "tool_meta" in dir() else "",
            completed_at=datetime.now(UTC).isoformat(),
        )
        raise RuntimeError(str(exc)) from None

    finally:
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# Hayabusa
# ─────────────────────────────────────────────────────────────────────────────


def _find_hayabusa_rules() -> Path | None:
    """Locate the Hayabusa rules/ directory.

    Tries (in order):
    1. Sibling of the real binary (follows symlinks) — works when the full
       distribution is kept next to the binary (e.g. /opt/hayabusa/).
    2. Hardcoded fallback /opt/hayabusa/rules.
    """
    bin_path = shutil.which("hayabusa")
    if bin_path:
        real_bin = Path(bin_path).resolve()
        candidate = real_bin.parent / "rules"
        if candidate.is_dir():
            return candidate
    fallback = Path("/opt/hayabusa/rules")
    if fallback.is_dir():
        return fallback
    return None


def _run_hayabusa(
    run_id: str,
    work_dir: Path,
    sources_dir: Path,
    params: dict,
    tool_meta: dict,
) -> list[dict]:
    hayabusa_bin = shutil.which("hayabusa")
    if not hayabusa_bin:
        raise RuntimeError(
            "Hayabusa binary not found. Ensure the processor image was built with the Hayabusa step."
        )

    rules_dir = _find_hayabusa_rules()
    if rules_dir is None:
        raise RuntimeError(
            "Hayabusa rules directory not found next to the binary or at /opt/hayabusa/rules. "
            "Rebuild the processor image — the full distribution (binary + rules/) must be kept together."
        )
    logger.info("[%s] Using Hayabusa rules: %s", run_id, rules_dir)

    # List EVTX files we are about to scan
    evtx_files = [
        p.name for p in sources_dir.iterdir() if p.is_file() and p.suffix.lower() == ".evtx"
    ]
    logger.info("[%s] EVTX files in sources_dir: %s", run_id, evtx_files)
    tool_meta["log"] = f"Rules: {rules_dir}\nEVTX files: {', '.join(evtx_files) or 'none'}\n"

    output_csv = work_dir / "hayabusa_output.csv"
    min_level = params.get("min_level", "informational")

    # csv-timeline is the most reliable output format across all Hayabusa 3.x versions.
    # The JSONL writer has had format-shift bugs between minor releases; CSV is stable.
    cmd = [
        hayabusa_bin,
        "csv-timeline",
        "--no-wizard",  # required since 3.x: suppress interactive wizard
        "-d",
        str(sources_dir),
        "-r",
        str(rules_dir),
        "-o",
        str(output_csv),
        "--min-level",
        min_level,
    ]

    logger.info("[%s] Running: %s", run_id, " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,  # prevent any interactive prompts
            timeout=3600,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Hayabusa timed out after 1 hour")

    # Strip ANSI escape codes before storing in Redis / displaying in UI
    stdout_str = _strip_ansi((proc.stdout or "").strip())
    stderr_str = _strip_ansi((proc.stderr or "").strip())

    # Combine both streams into tool_meta for display in the UI
    combined = ""
    if stdout_str:
        combined += stdout_str
    if stderr_str:
        combined += ("\n" if combined else "") + "[stderr]\n" + stderr_str
    tool_meta["stdout"] = combined
    tool_meta["log"] += f"\nReturn code: {proc.returncode}\n"

    if stdout_str:
        logger.info("[%s] Hayabusa stdout:\n%s", run_id, stdout_str[:3000])
    if stderr_str:
        logger.info("[%s] Hayabusa stderr:\n%s", run_id, stderr_str[:1000])

    if proc.returncode not in (0, 1):
        raise RuntimeError(
            f"Hayabusa exited {proc.returncode}: {(stderr_str or stdout_str or '')[:500]}"
        )

    if not output_csv.exists() or output_csv.stat().st_size == 0:
        detail = f"\n\nHayabusa output:\n{combined[:1000]}" if combined else ""
        logger.warning("[%s] Hayabusa produced no output file (or empty)%s", run_id, detail)
        return []

    file_size = output_csv.stat().st_size
    logger.info("[%s] Hayabusa output file: %d bytes", run_id, file_size)

    # ── Diagnostic: raw bytes peek into tool_stdout so it's visible in UI ────
    try:
        with open(output_csv, "rb") as _bf:
            _raw_bytes = _bf.read(600)
        _raw_text = _raw_bytes.decode("utf-8", errors="replace")
        tool_meta["stdout"] += (
            f"\n\n=== CSV output: {file_size:,} bytes ===\nFirst 600 bytes:\n{_raw_text}\n"
        )
    except Exception as _e:
        tool_meta["stdout"] += f"\n[file peek error: {_e}]\n"

    return _parse_hayabusa_csv(output_csv, tool_meta)


def _parse_hayabusa_csv(path: Path, tool_meta: dict | None = None) -> list[dict]:
    """Parse Hayabusa csv-timeline output into the hit list used by the module runner."""

    def _log(msg: str) -> None:
        if tool_meta is not None:
            tool_meta["log"] += msg

    _LEVEL_MAP = {
        "info": "informational",
        "information": "informational",
        "crit": "critical",
        "med": "medium",
        "warn": "medium",
        "warning": "medium",
    }

    results: list[dict] = []
    skipped = 0
    first_skip_msg = ""

    try:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            reader = csv.DictReader(fh)
            _log(f"\nCSV columns: {reader.fieldnames}\n")
            if tool_meta:
                tool_meta["stdout"] += f"\nCSV columns: {reader.fieldnames}\n"

            for lineno, row in enumerate(reader, 2):
                try:
                    rule_title = str(row.get("RuleTitle") or row.get("ruleTitle") or "")
                    ts_raw = str(row.get("Timestamp") or row.get("timestamp") or "")
                    if not rule_title and not ts_raw:
                        skipped += 1
                        if skipped == 1:
                            first_skip_msg = f"line {lineno}: missing RuleTitle+Timestamp"
                        continue

                    level = str(row.get("Level") or row.get("level") or "informational").lower()
                    level = _LEVEL_MAP.get(level, level)

                    details_raw = str(row.get("Details") or row.get("details") or "")
                    # CSV Details is always a string; may contain key: val | key: val
                    event_id_raw = str(row.get("EventID") or row.get("eventId") or "")
                    try:
                        event_id: int | None = int(event_id_raw) if event_id_raw else None
                    except ValueError:
                        event_id = None

                    # Tags column: comma-separated MITRE ATT&CK tags
                    # e.g. "attack.defense-evasion,attack.t1059.003"
                    tags_raw = str(row.get("Tags") or row.get("tags") or row.get("MitreTags") or "")
                    tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []

                    results.append(
                        {
                            "id": str(uuid.uuid4()),
                            "timestamp": _normalize_ts(ts_raw),
                            "level": level,
                            "level_int": LEVEL_INT.get(level, 1),
                            "rule_title": rule_title,
                            "computer": str(row.get("Computer") or row.get("computer") or ""),
                            "channel": str(row.get("Channel") or row.get("channel") or ""),
                            "event_id": event_id,
                            "details_raw": details_raw[:2000],
                            "rule_file": str(row.get("RuleFile") or row.get("ruleFile") or ""),
                            "evtx_file": str(row.get("EvtxFile") or row.get("evtxFile") or ""),
                            "tags": tags,
                        }
                    )
                except Exception as exc:
                    skipped += 1
                    if skipped <= 3:
                        logger.warning("Hayabusa CSV row %d error: %s", lineno, exc)
                    if skipped == 1:
                        first_skip_msg = f"line {lineno}: {exc}"

    except Exception as exc:
        _log(f"\n[CSV read error: {exc}]\n")
        return []

    summary = (
        f"\nParsed {len(results):,} CSV hits ({skipped:,} skipped)"
        + (f"\n{first_skip_msg}" if first_skip_msg else "")
        + "\n"
    )
    _log(summary)
    if tool_meta:
        tool_meta["stdout"] += f"\n=== Parser: {len(results):,} hits ({skipped:,} skipped) ===\n"
        if first_skip_msg:
            tool_meta["stdout"] += f"{first_skip_msg}\n"

    return results


def _hayabusa_index_to_es(
    case_id: str,
    run_id: str,
    hits: list[dict],
    ingested_at: str,
    bulk_size: int = 500,
) -> int:
    """Bulk-index Hayabusa hits into Elasticsearch as artifact_type=hayabusa events."""
    es_url = ELASTICSEARCH_URL.rstrip("/")
    indexed = 0

    def _flush(batch: list[dict]) -> None:
        nonlocal indexed
        lines = []
        for event in batch:
            index_name = f"fo-case-{case_id}-hayabusa"
            action = {"index": {"_index": index_name, "_id": event["fo_id"]}}
            lines.append(json.dumps(action))
            lines.append(json.dumps(event))
        body = "\n".join(lines) + "\n"
        req = urllib.request.Request(
            f"{es_url}/_bulk",
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/x-ndjson"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            if result.get("errors"):
                errs = [i for i in result.get("items", []) if i.get("index", {}).get("error")]
                logger.warning("Hayabusa ES bulk: %d errors in batch", len(errs))
        indexed += len(batch)

    batch: list[dict] = []
    for hit in hits:
        level = hit.get("level", "informational")
        computer = hit.get("computer", "")
        rule_title = hit.get("rule_title", "")
        message = f"[{level.upper()}] {rule_title}"
        if computer:
            message += f" on {computer}"

        event = {
            "fo_id": str(uuid.uuid4()),
            "case_id": case_id,
            "ingest_job_id": run_id,
            "source_file": f"module:hayabusa:{run_id}",
            "ingested_at": ingested_at,
            "artifact_type": "hayabusa",
            "timestamp": hit.get("timestamp", ""),
            "timestamp_desc": "Hayabusa Detection",
            "message": message,
            "host": {"hostname": computer},
            "hayabusa": {
                "rule_title": rule_title,
                "level": level,
                "level_int": hit.get("level_int", 1),
                "computer": computer,
                "channel": hit.get("channel", ""),
                "event_id": hit.get("event_id"),
                "details_raw": hit.get("details_raw", ""),
                "rule_file": hit.get("rule_file", ""),
                "evtx_file": hit.get("evtx_file", ""),
            },
            "tags": [],
            "analyst_note": "",
            "is_flagged": False,
            "mitre": {},
            "raw": {"line": json.dumps(hit, ensure_ascii=False)},
        }
        batch.append(event)
        if len(batch) >= bulk_size:
            _flush(batch)
            batch = []

    if batch:
        _flush(batch)

    return indexed


def _browser_report_index_to_es(
    case_id: str,
    run_id: str,
    results: list[dict],
    ingested_at: str,
    bulk_size: int = 500,
) -> int:
    """Bulk-index browser_report derived hits into ES as artifact_type=browser_report events.

    Skips `visits` (already in browser index) and `top_domains`/`summary`
    (aggregate stats with no timestamp). Indexes searches, downloads, logins.
    """
    es_url = ELASTICSEARCH_URL.rstrip("/")
    index_name = f"fo-case-{case_id}-browser_report"
    indexed = 0

    # Wipe the previous report so re-runs reflect current data only — the report
    # is derived from the browser raw index, so historical reports can drift.
    try:
        del_req = urllib.request.Request(f"{es_url}/{index_name}", method="DELETE")
        urllib.request.urlopen(del_req, timeout=30).read()
    except Exception:
        pass  # index may not exist on first run

    # Only sections without a usable timestamp/id are skipped. Summary still
    # gets indexed (so it shows on the timeline as a marker for the run).
    _SECTION_SKIP = {None}

    def _flush(batch: list[dict]) -> None:
        nonlocal indexed
        lines = []
        for event in batch:
            action = {"index": {"_index": index_name, "_id": event["fo_id"]}}
            lines.append(json.dumps(action))
            lines.append(json.dumps(event))
        body = "\n".join(lines) + "\n"
        req = urllib.request.Request(
            f"{es_url}/_bulk",
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/x-ndjson"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            if result.get("errors"):
                errs = [i for i in result.get("items", []) if i.get("index", {}).get("error")]
                logger.warning("browser_report ES bulk: %d errors in batch", len(errs))
        indexed += len(batch)

    batch: list[dict] = []
    for hit in results:
        section = hit.get("section")
        if section in _SECTION_SKIP:
            continue
        ts = hit.get("timestamp", "") or ingested_at
        try:
            details = json.loads(hit.get("details_raw", "{}"))
        except (json.JSONDecodeError, TypeError):
            details = {}

        event = {
            "fo_id": str(uuid.uuid4()),
            "case_id": case_id,
            "ingest_job_id": run_id,
            "source_file": f"module:browser_report:{run_id}",
            "ingested_at": ingested_at,
            "artifact_type": "browser_report",
            "timestamp": ts,
            "timestamp_desc": "Browser Report",
            "message": hit.get("rule_title", ""),
            "browser_report": {
                "section": section,
                "level": hit.get("level", "informational"),
                "level_int": hit.get("level_int", 1),
                "rule_title": hit.get("rule_title", ""),
                **{
                    k: v
                    for k, v in details.items()
                    if k not in ("timestamp",) and v not in (None, "", [])
                },
            },
            "tags": [],
            "analyst_note": "",
            "is_flagged": False,
            "host": {},
            "user": {},
            "process": {},
            "network": {},
            "raw": {},
        }
        batch.append(event)
        if len(batch) >= bulk_size:
            _flush(batch)
            batch = []

    if batch:
        _flush(batch)

    return indexed


# Built-in modules that must not be indexed generically (have their own indexers or are too noisy)
_MODULE_INDEX_SKIP = {"hayabusa", "browser_report"}

# artifact_type overrides for built-in modules whose module_id doesn't map cleanly to ES field name
_MODULE_ARTIFACT_TYPE: dict[str, str] = {
    "volatility3": "volatility",
}


def _generic_module_index_to_es(
    case_id: str,
    run_id: str,
    module_id: str,
    results: list[dict],
    ingested_at: str,
    bulk_size: int = 500,
) -> int:
    """Generic bulk-indexer for all module result hits.

    Maps module_id → artifact_type, stores full hit details in a
    sub-object keyed by the artifact_type name.
    """
    artifact_type = _MODULE_ARTIFACT_TYPE.get(
        module_id,
        module_id.replace("-", "_").replace(" ", "_"),
    )
    es_url = ELASTICSEARCH_URL.rstrip("/")
    index_name = f"fo-case-{case_id}-{artifact_type}"
    indexed = 0

    def _flush(batch: list[dict]) -> None:
        nonlocal indexed
        lines = []
        for event in batch:
            action = {"index": {"_index": index_name, "_id": event["fo_id"]}}
            lines.append(json.dumps(action))
            lines.append(json.dumps(event))
        body = "\n".join(lines) + "\n"
        req = urllib.request.Request(
            f"{es_url}/_bulk",
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/x-ndjson"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            if result.get("errors"):
                errs = [i for i in result.get("items", []) if i.get("index", {}).get("error")]
                logger.warning("%s ES bulk: %d errors in batch", module_id, len(errs))
        indexed += len(batch)

    batch: list[dict] = []
    for hit in results:
        try:
            details = json.loads(hit.get("details_raw", "{}"))
        except (json.JSONDecodeError, TypeError):
            details = {}

        ts = hit.get("timestamp", "") or ingested_at
        sub: dict = {
            "level": hit.get("level", "informational"),
            "level_int": hit.get("level_int", 1),
            "rule_title": hit.get("rule_title", ""),
        }
        if hit.get("section"):
            sub["section"] = hit["section"]
        # Merge details_raw fields, skip redundant/internal keys
        for k, v in details.items():
            if k not in ("timestamp", "level", "level_int", "rule_title") and v not in (
                None,
                "",
                [],
            ):
                sub[k] = v

        event = {
            "fo_id": str(uuid.uuid4()),
            "case_id": case_id,
            "ingest_job_id": run_id,
            "source_file": f"module:{module_id}:{run_id}",
            "ingested_at": ingested_at,
            "artifact_type": artifact_type,
            "timestamp": ts,
            "timestamp_desc": f"{artifact_type.replace('_', ' ').title()} Module",
            "message": hit.get("rule_title", ""),
            artifact_type: sub,
            "tags": [],
            "analyst_note": "",
            "is_flagged": False,
            "host": {},
            "user": {},
            "process": {},
            "network": {},
            "raw": {"line": hit.get("details_raw", "") or json.dumps(hit, ensure_ascii=False)},
        }
        batch.append(event)
        if len(batch) >= bulk_size:
            _flush(batch)
            batch = []

    if batch:
        _flush(batch)

    return indexed


def _parse_hayabusa_jsonl(path: Path, tool_meta: dict | None = None) -> list[dict]:
    """
    Parse Hayabusa output.  Handles two formats:
      • JSONL  – one JSON object per line  (Hayabusa default with .jsonl extension)
      • JSON   – a single JSON array       (Hayabusa -o file.json, pretty-print mode)

    Streams line-by-line for JSONL to avoid loading the full file into memory.
    utf-8-sig encoding handles UTF-8 BOM headers automatically.
    """

    def _log(msg: str) -> None:
        if tool_meta is not None:
            tool_meta["log"] += msg

    rows: list[dict] = []
    results: list[dict] = []
    skipped = 0
    total = 0
    first_skip_msg = ""

    # ── Peek at the first non-empty line to detect format ────────────────────
    first_line = ""
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            for raw_line in fh:
                stripped_line = raw_line.strip()
                if stripped_line:
                    first_line = stripped_line
                    break
    except Exception as exc:
        _log(f"\n[JSONL peek error: {exc}]\n")
        return []

    _log(f"\nFirst non-empty line (120 chars): {first_line[:120]}\n")

    if first_line.startswith("["):
        # ── JSON array format — full read required ────────────────────────
        try:
            with open(path, encoding="utf-8-sig", errors="replace") as fh:
                text = fh.read()
            data = json.loads(text)
            rows = data if isinstance(data, list) else [data]
            _log(f"\n[format: JSON array, {len(rows):,} entries]\n")
        except (json.JSONDecodeError, MemoryError) as exc:
            _log(f"\n[JSON array parse failed ({exc}); falling back to line-by-line]\n")
            rows = []
            try:
                with open(path, encoding="utf-8-sig", errors="replace") as fh:
                    for line in fh:
                        line = line.strip().rstrip(",")
                        if not line or line in ("[", "]"):
                            continue
                        try:
                            rows.append(json.loads(line))
                        except Exception:
                            pass
                _log(f"\n[format: JSON array (line fallback), {len(rows):,} entries]\n")
            except Exception as exc2:
                _log(f"\n[line fallback error: {exc2}]\n")
    else:
        # ── JSONL format — stream line-by-line ───────────────────────────
        parse_errors = 0
        try:
            with open(path, encoding="utf-8-sig", errors="replace") as fh:
                for lineno, raw_line in enumerate(fh, 1):
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        # Rare: some builds emit trailing commas
                        try:
                            rows.append(json.loads(line.rstrip(",")))
                        except Exception as exc:
                            parse_errors += 1
                            if parse_errors <= 3:
                                logger.warning(
                                    "Hayabusa: JSONL parse error line %d: %s | raw: %.120s",
                                    lineno,
                                    exc,
                                    line,
                                )
            _log(f"\n[format: JSONL, {len(rows):,} rows decoded, {parse_errors} parse errors]\n")
        except Exception as exc:
            _log(f"\n[JSONL streaming error: {exc}]\n")

    # ── Log first row for diagnostics ─────────────────────────────────────────
    if rows:
        first_row = rows[0]
        _log(f"\nFirst row keys: {list(first_row.keys())}\n")
        _log(f"First row sample: {str(first_row)[:400]}\n")
        # Also surface to tool_stdout so it's visible without scrolling to log
        if tool_meta is not None:
            tool_meta["stdout"] += f"\nFirst row keys: {list(first_row.keys())}\n"
    else:
        _log("\n[WARNING: 0 rows decoded from output file — check format above]\n")
        if tool_meta is not None:
            tool_meta["stdout"] += "\n[WARNING: 0 rows decoded from output file]\n"

    # ── Convert rows to hits ──────────────────────────────────────────────────
    for row in rows:
        if not isinstance(row, dict):
            skipped += 1
            continue
        total += 1
        try:
            hit = _hayabusa_row_to_hit(row)
            if hit:
                results.append(hit)
            else:
                skipped += 1
                if skipped == 1:
                    first_skip_msg = f"first skipped row keys: {list(row.keys())[:12]}"
        except Exception as exc:
            skipped += 1
            if skipped <= 3:
                logger.warning(
                    "Hayabusa: row conversion error: %s | keys: %s", exc, list(row.keys())[:8]
                )
            if skipped == 1:
                first_skip_msg = f"row error: {exc} | keys: {list(row.keys())[:8]}"

    logger.info("Hayabusa: %d rows, %d hits, %d skipped", total, len(results), skipped)
    summary = (
        f"\nDecoded {total:,} rows → {len(results):,} hits ({skipped:,} skipped)"
        + (f"\n{first_skip_msg}" if first_skip_msg else "")
        + "\n"
    )
    _log(summary)
    # Also surface parse summary to tool_stdout
    if tool_meta is not None:
        tool_meta["stdout"] += (
            f"\n=== Parser: {total:,} rows → {len(results):,} hits ({skipped:,} skipped) ==="
        )
        if first_skip_msg:
            tool_meta["stdout"] += f"\n{first_skip_msg}"
        tool_meta["stdout"] += "\n"
    return results


def _hayabusa_row_to_hit(row: dict) -> dict | None:
    # Accept PascalCase (2.x / 3.x standard), camelCase, snake_case, and @-prefixed variants
    def _g(*keys):
        for k in keys:
            v = row.get(k)
            if v is not None and v != "":
                return v
        return ""

    timestamp_raw = _g("Timestamp", "timestamp", "@timestamp", "datetime", "time")
    rule_title = str(
        _g("RuleTitle", "ruleTitle", "rule_title", "Title", "title", "RuleName", "rule_name") or ""
    )
    level = str(_g("Level", "level", "Severity", "severity") or "informational").lower()
    computer = str(_g("Computer", "computer", "Hostname", "hostname", "host") or "")
    channel = str(_g("Channel", "channel") or "")
    event_id_raw = str(_g("EventID", "eventId", "event_id", "EventId") or "")
    rule_file = str(_g("RuleFile", "ruleFile", "rule_file") or "")
    evtx_file = str(_g("EvtxFile", "evtxFile", "evtx_file", "SrcFile", "src_file") or "")

    if not rule_title and not timestamp_raw:
        return None

    # Details can be a dict (Hayabusa 3.x) or a plain string (2.x)
    raw_details = row.get("Details") or row.get("details") or ""
    if isinstance(raw_details, dict):
        # Flatten key: value pairs into a readable string
        details_raw = " | ".join(
            f"{k}: {v}" for k, v in raw_details.items() if v not in (None, "", "-")
        )
    else:
        details_raw = str(raw_details)

    try:
        event_id: int | None = int(event_id_raw) if event_id_raw else None
    except (ValueError, TypeError):
        event_id = None

    # Normalise level names across Hayabusa versions
    # 3.x: "crit", "high", "med", "low", "info"
    # 2.x: "critical", "high", "medium", "low", "informational"
    level_map = {
        "info": "informational",
        "information": "informational",
        "crit": "critical",
        "med": "medium",
        "warn": "medium",
        "warning": "medium",
    }
    level = level_map.get(level, level)

    return {
        "id": str(uuid.uuid4()),
        "timestamp": _normalize_ts(timestamp_raw),
        "level": level,
        "level_int": LEVEL_INT.get(level, 1),
        "rule_title": rule_title,
        "computer": computer,
        "channel": channel,
        "event_id": event_id,
        "details_raw": details_raw[:2000],
        "rule_file": rule_file,
        "evtx_file": evtx_file,
    }


def _normalize_ts(ts: str) -> str:
    """Normalize Hayabusa timestamp to ISO 8601 UTC."""
    if not ts:
        return ""
    ts = ts.strip()
    if len(ts) > 10 and ts[10] == " ":
        ts = ts[:10] + "T" + ts[11:]
    ts = ts.replace(" +", "+").replace(" -", "-")
    dot = ts.find(".")
    if dot != -1:
        end = dot + 1
        while end < len(ts) and ts[end].isdigit():
            end += 1
        frac = (ts[dot + 1 : end] + "000")[:3]
        ts = ts[: dot + 1] + frac + ts[end:]
    if ts.endswith("+00:00"):
        ts = ts[:-6] + "Z"
    elif not (ts.endswith("Z") or "+" in ts[10:] or (len(ts) > 19 and ts[-3] == ":")):
        ts += "Z"
    return ts


# ─────────────────────────────────────────────────────────────────────────────
# Hindsight
# ─────────────────────────────────────────────────────────────────────────────


def _run_hindsight(
    run_id: str, work_dir: Path, sources_dir: Path, params: dict, tool_meta: dict
) -> list[dict]:
    # pyhindsight installs a console script (hindsight.py) but has no __main__.py,
    # so `python -m hindsight` does NOT work.  Find the script file and invoke it
    # as `sys.executable script_path` so the correct interpreter is used regardless
    # of the shebang or PATH.
    hindsight_script = None

    # 1. Canonical pip scripts directory (most reliable — avoids PATH/shebang issues)
    scripts_dir = sysconfig.get_path("scripts")
    if scripts_dir:
        for name in ("hindsight.py", "hindsight"):
            candidate = os.path.join(scripts_dir, name)
            if os.path.isfile(candidate):
                hindsight_script = candidate
                break

    # 2. PATH fallback
    if not hindsight_script:
        for name in ("hindsight.py", "hindsight"):
            found = shutil.which(name)
            if found:
                hindsight_script = found
                break

    if not hindsight_script:
        installed = importlib.util.find_spec("hindsight") is not None
        msg = (
            f"pyhindsight is installed but hindsight.py was not found in {scripts_dir}. "
            "Try: pip3 install --force-reinstall pyhindsight"
            if installed
            else "hindsight not found. Ensure pyhindsight is installed in the processor image."
        )
        raise RuntimeError(msg)

    output_dir = work_dir / "hindsight_output"
    output_dir.mkdir()
    output_prefix = str(output_dir / "results")

    cmd = [
        sys.executable,
        hindsight_script,
        "-i",
        str(sources_dir),
        "-o",
        output_prefix,
        "-f",
        "jsonl",
    ]
    logger.info("[%s] Running: %s", run_id, " ".join(cmd))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Hindsight timed out after 10 minutes")

    # Hindsight may exit non-zero but still produce output
    jsonl_files = list(output_dir.glob("*.jsonl"))
    if not jsonl_files:
        if proc.returncode != 0:
            raise RuntimeError(
                f"Hindsight failed (code {proc.returncode}): {(proc.stderr or '')[:500]}"
            )
        return []

    return _parse_hindsight_jsonl(jsonl_files[0])


def _parse_hindsight_jsonl(jsonl_path: Path) -> list[dict]:
    """Parse hindsight JSONL output (one JSON object per line)."""
    results: list[dict] = []
    try:
        with open(jsonl_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(item, dict):
                    continue
                hit = _hindsight_item_to_hit(item)
                if hit:
                    results.append(hit)
    except Exception as exc:
        logger.warning("Failed to parse hindsight JSONL output: %s", exc)
    return results


def _hindsight_item_to_hit(item: dict) -> dict | None:
    url = str(item.get("url", item.get("value", ""))).strip()
    title = str(item.get("title", "")).strip()
    ts_raw = item.get("timestamp_UTC") or item.get("timestamp") or ""
    typ = str(item.get("type", "Browser Event")).strip()
    profile = str(item.get("profile", "")).strip()

    if not url and not title:
        return None

    details = url if not title or title == url else f"{url} — {title}"

    return {
        "id": str(uuid.uuid4()),
        "timestamp": _parse_hindsight_timestamp(ts_raw),
        "level": "informational",
        "level_int": 1,
        "rule_title": typ,
        "computer": profile,
        "details_raw": details,
        "url": url,
        "title": title,
    }


def _parse_hindsight_timestamp(ts) -> str:
    if not ts:
        return ""
    ts_str = str(ts).strip()

    # Human-readable UTC: "2023-01-15 14:32:11.123456"
    if len(ts_str) >= 19 and ts_str[10] == " ":
        clean = ts_str[:19].replace(" ", "T") + "Z"
        return clean

    # Chrome/WebKit microsecond timestamp (since 1601-01-01)
    try:
        ts_int = int(ts_str)
        if ts_int > 10**15:
            unix_ts = (ts_int / 1_000_000) - 11_644_473_600
            return datetime.fromtimestamp(unix_ts, tz=UTC).isoformat()
    except (ValueError, TypeError, OSError):
        pass

    return ts_str


# ─────────────────────────────────────────────────────────────────────────────
# RegRipper
# ─────────────────────────────────────────────────────────────────────────────

_RIP_PL = Path("/opt/regripper/rip.pl")


def _run_regripper(
    run_id: str, work_dir: Path, sources_dir: Path, params: dict, tool_meta: dict
) -> list[dict]:
    if not _RIP_PL.exists():
        raise RuntimeError(
            "RegRipper not found at /opt/regripper/rip.pl. "
            "Ensure the processor image was built with the RegRipper step."
        )

    results: list[dict] = []

    for file_path in sorted(sources_dir.iterdir()):
        if not file_path.is_file():
            continue

        profile = _regripper_profile(file_path.name)
        logger.info("[%s] RegRipper: %s (profile: %s)", run_id, file_path.name, profile)

        try:
            proc = subprocess.run(
                ["perl", str(_RIP_PL), "-r", str(file_path), "-f", profile],
                capture_output=True,
                text=True,
                timeout=300,
                cwd="/opt/regripper",
            )
        except subprocess.TimeoutExpired:
            logger.warning("[%s] RegRipper timed out on %s", run_id, file_path.name)
            continue

        hits = _parse_regripper_output(proc.stdout, file_path.name)
        results.extend(hits)

        if not hits and proc.returncode not in (0, 1):
            logger.warning(
                "[%s] RegRipper code %d for %s: %s",
                run_id,
                proc.returncode,
                file_path.name,
                (proc.stderr or "")[:200],
            )

    return results


def _regripper_profile(filename: str) -> str:
    name = os.path.basename(filename).upper()
    if "NTUSER" in name or "USRCLASS" in name:
        return "ntuser"
    if name == "SYSTEM":
        return "system"
    if name == "SOFTWARE":
        return "software"
    if name == "SAM":
        return "sam"
    if name == "SECURITY":
        return "security"
    return "ntuser"


def _parse_regripper_output(output: str, filename: str) -> list[dict]:
    """Parse RegRipper text output (blocks separated by --- lines) into hit dicts."""
    results: list[dict] = []

    blocks = re.split(r"^-{10,}$", output, flags=re.MULTILINE)
    for block in blocks:
        block = block.strip()
        if not block or len(block) < 10:
            continue

        lines = block.splitlines()
        if not lines:
            continue

        # First line: "PluginName v.YYYYMMDD"
        first = lines[0].strip()
        plugin_name = first.split(" v.")[0].strip() if " v." in first else first[:60]

        # Skip the hive-path line "(HIVENAME)" if present
        body_lines = []
        for line in lines[1:]:
            stripped = line.strip()
            if stripped.startswith("(") and stripped.endswith(")"):
                continue
            body_lines.append(line)

        content = "\n".join(body_lines).strip()
        if not content or len(content) < 5:
            continue

        results.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": "",
                "level": "informational",
                "level_int": 1,
                "rule_title": plugin_name,
                "computer": filename,  # hive filename
                "details_raw": content[:2000],  # cap per hit
            }
        )

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Windows Artifact Triage
# Handles: .evtx · registry hives · .lnk · .pf (Prefetch)
# ─────────────────────────────────────────────────────────────────────────────

_EVTX_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Interesting Windows event IDs for forensic triage: {eid: (label, level)}
_INTERESTING_EIDS: dict[int, tuple[str, str]] = {
    # Authentication & Lateral Movement
    4624: ("Logon", "medium"),
    4625: ("Failed Logon", "high"),
    4648: ("Explicit-Credential Logon", "high"),
    4672: ("Special Privileges Logon", "medium"),
    4776: ("NTLM Auth Attempt", "medium"),
    4778: ("RDP Session Reconnected", "medium"),
    4779: ("RDP Session Disconnected", "low"),
    # Account Management
    4720: ("User Account Created", "high"),
    4722: ("Account Enabled", "medium"),
    4724: ("Password Reset", "high"),
    4732: ("Added to Local Group", "high"),
    4756: ("Added to Universal Group", "medium"),
    4728: ("Added to Global Group", "high"),
    # Process / Execution Evidence
    4688: ("Process Created", "medium"),
    4689: ("Process Terminated", "low"),
    # Service / Driver
    7045: ("Service Installed", "high"),
    7034: ("Service Crashed", "medium"),
    7036: ("Service State Changed", "low"),
    4697: ("Service Installed (Security)", "high"),
    # Scheduled Tasks
    4698: ("Scheduled Task Created", "high"),
    4702: ("Scheduled Task Updated", "medium"),
    4699: ("Scheduled Task Deleted", "high"),
    # PowerShell
    4103: ("PS Module Logging", "medium"),
    4104: ("PS Script Block", "high"),
    # Audit Tampering
    1102: ("Security Log Cleared", "critical"),
    104: ("System Log Cleared", "critical"),
    4719: ("System Audit Policy Changed", "high"),
    # Policy / Object Access
    4670: ("Permissions Changed", "medium"),
    4663: ("Object Access Attempted", "low"),
    # Network (Windows Firewall)
    5156: ("Network Connection Allowed", "low"),
    5158: ("Network Bind Allowed", "low"),
    # BITS (common persistence / exfil channel)
    59: ("BITS Job Created", "medium"),
    60: ("BITS Job Transferred", "low"),
    # System lifecycle
    6005: ("Event Log Started", "low"),
    6006: ("Event Log Stopped", "low"),
    6009: ("OS Version at Boot", "low"),
}

MAX_EVTX_HITS = 3000  # per-file cap

# Registry paths to examine per hive type (paths relative to hive root)
_REG_TRIAGE_PATHS: dict[str, list[tuple[str, str]]] = {
    "ntuser": [
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run (Persistence)"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce (Persistence)"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", "Recent Documents"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths", "Explorer Typed Paths"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", "Run Dialog MRU"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Search\RecentApps", "Recent Apps"),
        (r"SOFTWARE\Microsoft\Internet Explorer\TypedURLs", "IE Typed URLs"),
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
            "Open/Save Dialog MRU",
        ),
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU",
            "Mapped Drives MRU",
        ),
    ],
    "usrclass": [
        (
            r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
            "Shell Bags (folder navigation)",
        ),
        (
            r"Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages",
            "Installed UWP Apps",
        ),
    ],
    "software": [
        (r"Microsoft\Windows\CurrentVersion\Run", "HKLM Run (Persistence)"),
        (r"Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce (Persistence)"),
        (r"WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run WOW64 (Persistence)"),
        (r"Microsoft\Windows NT\CurrentVersion", "OS Version / Install Date"),
        (r"Microsoft\Windows NT\CurrentVersion\ProfileList", "User Profile List"),
        (r"Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon (possible persistence)"),
        (r"Microsoft\Windows\CurrentVersion\Policies\System", "UAC & Policy Settings"),
        (r"Clients\StartMenuInternet", "Default Browser"),
    ],
    "system": [
        (r"ControlSet001\Control\ComputerName\ComputerName", "Computer Name"),
        (r"ControlSet001\Control\TimeZoneInformation", "Timezone"),
        (r"ControlSet001\Services", "Services (persistence)"),
        (r"ControlSet001\Control\Session Manager\AppCompatCache", "AppCompatCache / ShimCache"),
        (r"MountedDevices", "Mounted Devices (USB evidence)"),
        (r"ControlSet001\Enum\USBSTOR", "USB Storage History"),
    ],
    "sam": [
        (r"SAM\Domains\Account\Users\Names", "Local User Accounts"),
        (r"SAM\Domains\Account", "Account Policy"),
    ],
    "security": [],  # binary-heavy; RegRipper handles it better
}

MAX_REG_VALUES = 60  # per key


def _hive_type(filename: str) -> str:
    n = os.path.basename(filename).upper()
    if "NTUSER" in n:
        return "ntuser"
    if "USRCLASS" in n:
        return "usrclass"
    if n == "SYSTEM":
        return "system"
    if n == "SOFTWARE":
        return "software"
    if n == "SAM":
        return "sam"
    if n == "SECURITY":
        return "security"
    return "ntuser"


# ── EVTX ─────────────────────────────────────────────────────────────────────


def _parse_evtx_triage(file_path: Path) -> list[dict]:
    try:
        import Evtx.Evtx as evtx_lib
    except ImportError:
        logger.warning("[wintriage] python-evtx not installed, skipping EVTX")
        return []

    ns = _EVTX_NS
    results: list[dict] = []

    try:
        with evtx_lib.Evtx(str(file_path)) as log:
            for record in log.records():
                if len(results) >= MAX_EVTX_HITS:
                    break
                try:
                    root = record.lxml()
                    sys_el = root.find(f"{{{ns}}}System")
                    if sys_el is None:
                        continue

                    eid_el = sys_el.find(f"{{{ns}}}EventID")
                    if eid_el is None:
                        continue
                    try:
                        event_id = int(eid_el.text)
                    except (ValueError, TypeError):
                        continue

                    if event_id not in _INTERESTING_EIDS:
                        continue

                    label, level = _INTERESTING_EIDS[event_id]

                    tc_el = sys_el.find(f"{{{ns}}}TimeCreated")
                    ts = tc_el.get("SystemTime", "") if tc_el is not None else ""

                    comp_el = sys_el.find(f"{{{ns}}}Computer")
                    computer = (comp_el.text or "") if comp_el is not None else ""

                    chan_el = sys_el.find(f"{{{ns}}}Channel")
                    channel = (chan_el.text or "") if chan_el is not None else ""

                    # EventData key-value pairs
                    ed_el = root.find(f"{{{ns}}}EventData")
                    parts: list[str] = []
                    if ed_el is not None:
                        for data_el in ed_el:
                            name = data_el.get("Name", "")
                            val = (data_el.text or "").strip()
                            if name and val and val not in ("-", "%%1840", "%%1843", "%%1842"):
                                parts.append(f"{name}: {val}")
                    details = " | ".join(parts[:7])

                    results.append(
                        {
                            "id": str(uuid.uuid4()),
                            "timestamp": ts,
                            "level": level,
                            "level_int": LEVEL_INT.get(level, 1),
                            "rule_title": f"EID {event_id}: {label}",
                            "computer": computer,
                            "details_raw": f"[{channel}] {details}" if details else f"[{channel}]",
                        }
                    )
                except Exception:
                    continue
    except Exception as exc:
        logger.warning("[wintriage] EVTX error %s: %s", file_path.name, exc)

    return results


# ── Registry ──────────────────────────────────────────────────────────────────


def _parse_registry_triage(file_path: Path) -> list[dict]:
    try:
        from Registry import Registry as RegistryLib
    except ImportError:
        logger.warning("[wintriage] python-registry not installed, skipping registry")
        return []

    hive_type = _hive_type(file_path.name)
    triage_paths = _REG_TRIAGE_PATHS.get(hive_type, [])
    if not triage_paths:
        return []

    try:
        reg = RegistryLib.Registry(str(file_path))
    except Exception as exc:
        logger.warning("[wintriage] Cannot open registry %s: %s", file_path.name, exc)
        return []

    results: list[dict] = []

    for key_path, label in triage_paths:
        try:
            key = reg.open(key_path)
        except Exception:
            continue  # key absent in this hive variant

        try:
            ts_dt = key.timestamp()
            ts = ts_dt.isoformat() + "Z" if ts_dt else ""
        except Exception:
            ts = ""

        values_found = 0
        for val in key.values():
            if values_found >= MAX_REG_VALUES:
                break
            try:
                name = val.name() or "(Default)"
                data = str(val.value())[:600]
                if not data.strip():
                    continue
            except Exception:
                continue
            results.append(
                {
                    "id": str(uuid.uuid4()),
                    "timestamp": ts,
                    "level": "informational",
                    "level_int": 1,
                    "rule_title": f"{label}: {name}",
                    "computer": file_path.name,
                    "details_raw": data,
                }
            )
            values_found += 1

        # No values → list subkey names as a single summary hit
        if values_found == 0:
            try:
                subkeys = [sk.name() for sk in list(key.subkeys())[:MAX_REG_VALUES]]
                if subkeys:
                    results.append(
                        {
                            "id": str(uuid.uuid4()),
                            "timestamp": ts,
                            "level": "informational",
                            "level_int": 1,
                            "rule_title": f"{label} (subkeys)",
                            "computer": file_path.name,
                            "details_raw": " | ".join(subkeys),
                        }
                    )
            except Exception:
                pass

    return results


# ── LNK ──────────────────────────────────────────────────────────────────────


def _parse_lnk_triage(file_path: Path) -> list[dict]:
    try:
        import LnkParse3
    except ImportError:
        logger.warning("[wintriage] LnkParse3 not installed, skipping LNK")
        return []

    try:
        with open(file_path, "rb") as fh:
            lnk = LnkParse3.lnk_file(fh)
            data = lnk.get_json()
    except Exception as exc:
        logger.debug("[wintriage] LNK parse failed %s: %s", file_path.name, exc)
        return []

    header = data.get("header", {}) or {}
    link_info = data.get("link_info", {}) or {}
    string_data = data.get("string_data", {}) or {}

    ts = header.get("creation_time") or header.get("write_time") or ""
    # LnkParse3 may return datetime.datetime objects instead of strings
    if isinstance(ts, datetime):
        ts = ts.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    elif ts:
        ts = str(ts)
        if not ts.endswith("Z"):
            ts = ts.replace(" ", "T") + "Z"

    target_path = (
        link_info.get("local_base_path")
        or string_data.get("relative_path")
        or string_data.get("working_dir")
        or file_path.stem
    )

    vol_info = link_info.get("volume_id_and_local_base_path") or {}
    vol_label = vol_info.get("volume_label", "") if isinstance(vol_info, dict) else ""
    machine = string_data.get("machine_identifier", "")
    cmd_args = string_data.get("command_line_arguments", "")

    details = target_path or file_path.stem
    if vol_label:
        details += f"  [Vol: {vol_label}]"
    if cmd_args:
        details += f"  Args: {cmd_args}"
    if machine:
        details += f"  Machine: {machine}"

    return [
        {
            "id": str(uuid.uuid4()),
            "timestamp": ts,
            "level": "informational",
            "level_int": 1,
            "rule_title": f"LNK: {file_path.stem}",
            "computer": machine or "",
            "details_raw": details,
        }
    ]


# ── Prefetch ──────────────────────────────────────────────────────────────────

_PF_RUN_COUNT_OFFSET: dict[int, int] = {
    17: 0x90,  # Windows XP
    23: 0x98,  # Windows Vista / 7
    26: 0xD0,  # Windows 8 / 8.1
    30: 0xD0,  # Windows 10 (uncompressed only)
}


def _parse_prefetch_triage(file_path: Path) -> list[dict]:
    stem = file_path.stem  # e.g. NOTEPAD.EXE-AB1234CD
    parts = stem.rsplit("-", 1)
    exe_name = parts[0] if len(parts) == 2 else stem
    pf_hash = parts[1] if len(parts) == 2 else ""

    try:
        mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=UTC).isoformat()
    except Exception:
        mtime = ""

    run_count = None
    version_note = ""

    try:
        with open(file_path, "rb") as fh:
            header = fh.read(512)

        if header[:3] == b"MAM":
            version_note = "Win10 (MAM-compressed)"
        elif header[4:8] == b"SCCA" and len(header) >= 8:
            ver = struct.unpack_from("<I", header, 0)[0]
            offset = _PF_RUN_COUNT_OFFSET.get(ver)
            if offset and len(header) >= offset + 4:
                run_count = struct.unpack_from("<I", header, offset)[0]
            version_note = {17: "WinXP", 23: "Vista/7", 26: "Win8.x", 30: "Win10"}.get(
                ver, f"v{ver}"
            )
        else:
            version_note = "unknown format"
    except Exception:
        pass

    details = exe_name
    if pf_hash:
        details += f"  hash={pf_hash}"
    if run_count is not None:
        details += f"  run_count={run_count}"
    if version_note:
        details += f"  [{version_note}]"

    return [
        {
            "id": str(uuid.uuid4()),
            "timestamp": mtime,
            "level": "informational",
            "level_int": 1,
            "rule_title": f"Prefetch: {exe_name}",
            "computer": "",
            "details_raw": details,
        }
    ]


# ── Main dispatcher ───────────────────────────────────────────────────────────

_REGISTRY_FILENAMES = frozenset(
    {"NTUSER.DAT", "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "USRCLASS.DAT"}
)
_REGISTRY_EXTENSIONS = frozenset({".dat", ".hive"})


def _run_wintriage(
    run_id: str, work_dir: Path, sources_dir: Path, params: dict, tool_meta: dict
) -> list[dict]:
    """
    Auto-detect Windows artifact type and run the appropriate parser.

      .evtx              → EVTX triage (filtered to ~35 high-value event IDs)
      .dat / .hive /
      SYSTEM / SOFTWARE /
      SAM / SECURITY /
      NTUSER.DAT         → Registry triage (persistence + forensic key paths)
      .lnk               → LNK (target path, timestamps, machine ID)
      .pf                → Prefetch (execution evidence + run count)
    """
    results: list[dict] = []

    for file_path in sorted(sources_dir.iterdir()):
        if not file_path.is_file():
            continue

        name_upper = file_path.name.upper()
        ext = file_path.suffix.lower()

        if ext == ".evtx":
            logger.info("[%s] wintriage EVTX: %s", run_id, file_path.name)
            hits = _parse_evtx_triage(file_path)

        elif name_upper in _REGISTRY_FILENAMES or ext in _REGISTRY_EXTENSIONS:
            logger.info("[%s] wintriage Registry: %s", run_id, file_path.name)
            hits = _parse_registry_triage(file_path)

        elif ext == ".lnk":
            logger.info("[%s] wintriage LNK: %s", run_id, file_path.name)
            hits = _parse_lnk_triage(file_path)

        elif ext == ".pf":
            logger.info("[%s] wintriage Prefetch: %s", run_id, file_path.name)
            hits = _parse_prefetch_triage(file_path)

        else:
            logger.debug("[%s] wintriage skip: %s", run_id, file_path.name)
            continue

        logger.info("[%s] %s → %d hits", run_id, file_path.name, len(hits))
        results.extend(hits)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# YARA Scanner
# ─────────────────────────────────────────────────────────────────────────────

# Built-in ruleset — 16 rules covering common malware patterns and threat-hunting
_YARA_RULES_SOURCE = r"""
rule SuspiciousPE_Packer {
    meta:
        description = "Detects common PE packer signatures"
        severity = "medium"
    strings:
        $upx0   = "UPX0"    ascii
        $upx1   = "UPX1"    ascii
        $upx2   = "UPX2"    ascii
        $aspack = "ASPack"  ascii
        $fsg    = ".ndata"  ascii
        $mpress = "MPRESS1" ascii
    condition:
        2 of them
}

rule SuspiciousScript_PowerShellEncoded {
    meta:
        description = "Detects base64-encoded or obfuscated PowerShell commands"
        severity = "high"
    strings:
        $enc1 = "-EncodedCommand"  ascii nocase
        $enc3 = "FromBase64String" ascii nocase
        $enc4 = "JABlAG4AYwBvAGQA" ascii
        $iex1 = "Invoke-Expression" ascii nocase
        $iex2 = "IEX("             ascii nocase
        $byp1 = "bypass"           ascii nocase
        $byp2 = "DownloadString"   ascii nocase
        $byp3 = "DownloadFile"     ascii nocase
    condition:
        2 of ($enc*) or any of ($iex*) or (any of ($byp*) and any of ($enc*))
}

rule SuspiciousShell_ReverseShell {
    meta:
        description = "Detects common reverse shell patterns"
        severity = "critical"
    strings:
        $nc1  = "nc -e /bin/bash"         ascii nocase
        $nc2  = "nc -e /bin/sh"           ascii nocase
        $nc3  = "/bin/bash -i >& /dev/tcp/" ascii
        $nc4  = "bash -i >& /dev/tcp/"    ascii
        $perl = "perl -e 'use Socket"     ascii nocase
        $py1  = "python -c 'import socket" ascii nocase
        $py2  = "python3 -c 'import socket" ascii nocase
    condition:
        any of them
}

rule SuspiciousStrings_Credentials {
    meta:
        description = "Detects hard-coded credential patterns"
        severity = "high"
    strings:
        $pass1 = "password="  ascii nocase
        $pass2 = "passwd="    ascii nocase
        $api1  = "api_key"    ascii nocase
        $api2  = "apikey"     ascii nocase
        $sec1  = "secret_key" ascii nocase
        $sec2  = "aws_secret" ascii nocase
        $tok1  = "bearer "    ascii nocase
    condition:
        2 of them
}

rule Mimikatz_Indicators {
    meta:
        description = "Detects Mimikatz credential dumping tool signatures"
        severity = "critical"
    strings:
        $s1 = "mimikatz"       ascii nocase
        $s2 = "sekurlsa::"     ascii nocase
        $s3 = "lsadump::"      ascii nocase
        $s4 = "kerberos::"     ascii nocase
        $s5 = "privilege::debug" ascii nocase
        $s6 = "SamSs"          ascii wide
        $s7 = "wdigest"        ascii wide
    condition:
        2 of them
}

rule Webshell_PHP {
    meta:
        description = "Detects common PHP webshell patterns"
        severity = "critical"
    strings:
        $p1 = "eval(base64_decode("  ascii nocase
        $p2 = "eval(gzinflate("      ascii nocase
        $p3 = "eval(str_rot13("      ascii nocase
        $p4 = "eval($_POST["         ascii nocase
        $p5 = "system($_GET["        ascii nocase
        $p6 = "exec($_REQUEST["      ascii nocase
        $p7 = "passthru($_"          ascii nocase
    condition:
        any of them
}

rule Ransomware_ExtensionTargets {
    meta:
        description = "Detects ransomware-like file extension targeting patterns"
        severity = "high"
    strings:
        $ext2 = "encrypt"                    ascii nocase
        $ext3 = "ransom"                     ascii nocase
        $ext4 = "YOUR_FILES_ARE_ENCRYPTED"   ascii nocase
        $ext5 = "HOW_TO_DECRYPT"             ascii nocase
        $ext6 = "RECOVERY_KEY"               ascii nocase
        $ext7 = "bitcoin"                    ascii nocase
    condition:
        2 of them
}

rule CobaltStrike_Beacon {
    meta:
        description = "Detects CobaltStrike beacon patterns and default strings"
        severity = "critical"
    strings:
        $s1 = "ReflectiveLoader"       ascii
        $s2 = "beacon.dll"             ascii nocase
        $s3 = "cobaltstrike"           ascii nocase
        $s4 = "sleep_mask"             ascii
        $s5 = "%s (admin)"             ascii
        $s6 = "post-ex"                ascii
        $b1 = { 68 74 74 70 73 3A 2F 2F }   // "https://" in shellcode context
        $w1 = "www6"                   ascii
        $w2 = "cdn."                   ascii
    condition:
        2 of ($s*) or ($b1 and 1 of ($w*))
}

rule Metasploit_Meterpreter {
    meta:
        description = "Detects Metasploit/Meterpreter staging and session strings"
        severity = "critical"
    strings:
        $m1 = "meterpreter"     ascii nocase
        $m2 = "metasploit"      ascii nocase
        $m3 = "Msf::"           ascii
        $m4 = "PAYLOAD_UUID"    ascii
        $m5 = "stageless"       ascii nocase
        $sh1 = "windows/meterpreter" ascii nocase
        $sh2 = "linux/x86/meterpreter" ascii nocase
    condition:
        any of them
}

rule Persistence_Registry_AppInit {
    meta:
        description = "Detects AppInit_DLLs and other covert registry persistence keys"
        severity = "high"
    strings:
        $k1 = "AppInit_DLLs"        ascii nocase wide
        $k2 = "AppCertDlls"         ascii nocase wide
        $k3 = "Notify\\"            ascii nocase wide
        $k4 = "SecurityProviders"   ascii nocase wide
        $k5 = "LSA\\Authentication" ascii nocase wide
        $k6 = "Print\\Providers"    ascii nocase wide
        $k7 = "Winsock2\\Parameters\\Protocol_Catalog9" ascii nocase wide
    condition:
        any of them
}

rule ProcessInjection_APIs {
    meta:
        description = "Detects common process injection API call sequences"
        severity = "high"
    strings:
        $va   = "VirtualAllocEx"     ascii wide
        $wpm  = "WriteProcessMemory" ascii wide
        $ct   = "CreateRemoteThread" ascii wide
        $nt1  = "NtCreateThreadEx"   ascii wide
        $nt2  = "NtMapViewOfSection" ascii wide
        $apc  = "QueueUserAPC"       ascii wide
        $sh   = "SetWindowsHookEx"   ascii wide
    condition:
        3 of them
}

rule LOLBIN_Abuse {
    meta:
        description = "Detects Living-off-the-Land Binary abuse patterns"
        severity = "high"
    strings:
        $c1 = "certutil" ascii nocase
        $c2 = "-decode"  ascii nocase
        $c3 = "-urlcache" ascii nocase
        $r1 = "regsvr32" ascii nocase
        $r2 = "scrobj.dll" ascii nocase
        $b1 = "bitsadmin"  ascii nocase
        $b2 = "/transfer"  ascii nocase
        $w1 = "wmic"       ascii nocase
        $w2 = "process call create" ascii nocase
        $m1 = "mshta"      ascii nocase
        $m2 = "vbscript"   ascii nocase
    condition:
        ($c1 and 1 of ($c2, $c3)) or
        ($r1 and $r2) or
        ($b1 and $b2) or
        ($w1 and $w2) or
        ($m1 and $m2)
}

rule LateralMovement_PsExec {
    meta:
        description = "Detects PsExec and common lateral movement tool artifacts"
        severity = "high"
    strings:
        $px1 = "PSEXESVC"      ascii wide nocase
        $px2 = "psexec"        ascii nocase
        $wm1 = "wmiexec"       ascii nocase
        $wm2 = "Win32_Process" ascii wide
        $sm1 = "smbexec"       ascii nocase
        $at1 = "atexec"        ascii nocase
        $dc  = "dcomexec"      ascii nocase
    condition:
        any of them
}

rule SuspiciousOfficeDoc_Macro {
    meta:
        description = "Detects suspicious VBA macro execution patterns in Office documents"
        severity = "high"
    strings:
        $v1 = "Auto_Open"     ascii nocase
        $v2 = "Document_Open" ascii nocase
        $v3 = "AutoOpen"      ascii nocase
        $v4 = "Shell("        ascii nocase
        $v5 = "CreateObject(" ascii nocase
        $v6 = "WScript.Shell" ascii nocase
        $v7 = "cmd.exe"       ascii nocase
    condition:
        2 of ($v1, $v2, $v3) or (1 of ($v1, $v2, $v3) and 1 of ($v4, $v5, $v6, $v7))
}

rule DataStaging_Exfil {
    meta:
        description = "Detects data staging and potential exfiltration indicators"
        severity = "medium"
    strings:
        $z1 = "7z.exe"        ascii nocase
        $z2 = "WinRAR"        ascii nocase
        $z3 = ".7z"           ascii nocase
        $f1 = "passwords"     ascii nocase
        $f2 = "credentials"   ascii nocase
        $f3 = "sensitive"     ascii nocase
        $u1 = "ftp://"        ascii nocase
        $u2 = "pastebin.com"  ascii nocase
        $u3 = "mega.nz"       ascii nocase
    condition:
        (1 of ($z*) and 1 of ($f*)) or
        (1 of ($f*) and 1 of ($u*))
}

rule CryptoMiner {
    meta:
        description = "Detects cryptocurrency miner strings and configuration"
        severity = "high"
    strings:
        $s1 = "xmrig"         ascii nocase
        $s2 = "stratum+tcp://" ascii nocase
        $s3 = "monero"        ascii nocase
        $s4 = "--donate-level" ascii nocase
        $s5 = "pool.minexmr"  ascii nocase
        $s6 = "cryptonight"   ascii nocase
        $s7 = "nicehash"      ascii nocase
        $s8 = "2miners.com"   ascii nocase
    condition:
        2 of them
}
"""


def _compile_yara_rules(custom_rules_source: str | None = None):
    """Compile YARA rules from the built-in set, optionally merging custom rules."""
    import yara

    source = _YARA_RULES_SOURCE
    if custom_rules_source and custom_rules_source.strip():
        source = source + "\n\n" + custom_rules_source.strip()
    return yara.compile(source=source)


def _load_yara_library_rules(
    run_id: str,
    selected_ids: list[str] | None = None,
    case_company: str = "",
) -> str:
    """
    Fetch YARA rules from the library (Redis).
    If selected_ids is provided, only those rule IDs are included.
    If case_company is provided, rules with a non-empty companies list are only
    included when case_company is in that list.
    Each rule is compiled individually before inclusion — bad rules are skipped with a warning
    so one invalid rule never prevents the rest from running.
    """
    try:
        import yara

        r = get_redis()
        all_ids = r.smembers(rk.YARA_RULES_SET)
        if not all_ids:
            return ""

        # Normalise to strings
        str_ids = {(rid.decode() if isinstance(rid, bytes) else rid) for rid in all_ids}

        # Apply selection filter if provided
        if selected_ids is not None:
            str_ids = str_ids & set(selected_ids)

        parts: list[str] = []
        skipped = 0
        for rid in str_ids:
            key = rk.yara_rule(rid)
            # Company-scoped filter
            if case_company:
                raw_cos = r.hget(key, "companies")
                cos_str = (raw_cos.decode() if isinstance(raw_cos, bytes) else raw_cos) or "[]"
                try:
                    rule_companies = json.loads(cos_str)
                except Exception:
                    rule_companies = []
                if rule_companies and case_company not in rule_companies:
                    continue
            content = r.hget(key, "content")
            if not content:
                continue
            content_str = content.decode() if isinstance(content, bytes) else content
            # Validate before including — skip rules that don't compile cleanly
            try:
                yara.compile(source=content_str)
                parts.append(content_str)
            except Exception as exc:
                skipped += 1
                logger.warning(
                    "[%s] YARA: skipping library rule %s (compilation error): %s", run_id, rid, exc
                )

        if skipped:
            logger.warning("[%s] YARA: skipped %d invalid library rule(s)", run_id, skipped)
        if parts:
            logger.info("[%s] YARA: loaded %d valid library rule(s)", run_id, len(parts))
        return "\n\n".join(parts)
    except Exception as exc:
        logger.warning("[%s] YARA: could not load library rules: %s", run_id, exc)
        return ""


def _run_yara(
    run_id: str,
    work_dir: Path,
    sources_dir: Path,
    params: dict,
    tool_meta: dict,
) -> list[dict]:
    """Scan source files with YARA rules (built-in + library + optional custom rules)."""
    custom_rules = params.get("custom_rules", "") or ""
    use_library = params.get("use_library_rules", True)
    selected_ids = params.get("selected_rule_ids", None)  # list[str] | None
    case_company = params.get("case_company", "") or ""

    # Merge library rules (fetched from Redis) with any inline custom rules from the run params
    library_rules = (
        _load_yara_library_rules(run_id, selected_ids, case_company) if use_library else ""
    )
    all_extra = "\n\n".join(s for s in [custom_rules.strip(), library_rules.strip()] if s)

    try:
        import yara
    except ImportError:
        yara_bin = shutil.which("yara")
        if not yara_bin:
            raise RuntimeError(
                "yara-python is not installed and the yara CLI binary is not in PATH. "
                "Ensure yara-python is installed in the processor image (pip install yara-python)."
            )
        return _run_yara_cli(run_id, work_dir, sources_dir, yara_bin, params, tool_meta)

    # Compile built-in rules + library rules + any custom rules
    try:
        rules = _compile_yara_rules(all_extra if all_extra else None)
    except Exception as exc:
        raise RuntimeError(f"YARA rule compilation failed: {exc}") from exc

    n_custom = custom_rules.strip().count("rule ") if custom_rules.strip() else 0
    n_library = library_rules.strip().count("rule ") if library_rules.strip() else 0
    tool_meta["log"] = f"Built-in rules + {n_library} library rule(s) + {n_custom} custom rule(s)\n"

    _SEVERITY_MAP = {
        "critical": ("critical", 5),
        "high": ("high", 4),
        "medium": ("medium", 3),
        "low": ("low", 2),
    }

    results: list[dict] = []

    for file_path in sorted(sources_dir.iterdir()):
        if not file_path.is_file():
            continue
        logger.info("[%s] YARA scanning: %s", run_id, file_path.name)
        try:
            matches = rules.match(str(file_path), timeout=60)
        except yara.TimeoutError:
            logger.warning("[%s] YARA timeout on %s", run_id, file_path.name)
            continue
        except Exception as exc:
            logger.debug("[%s] YARA error on %s: %s", run_id, file_path.name, exc)
            continue

        for match in matches:
            sev_raw = (match.meta.get("severity") or "medium").lower()
            level, lint = _SEVERITY_MAP.get(sev_raw, ("medium", 3))
            description = match.meta.get("description", "")
            strings_info = ", ".join(
                f"{s.identifier}@{s.instances[0].offset:#x}" if s.instances else s.identifier
                for s in match.strings[:5]
            )
            results.append(
                {
                    "id": str(uuid.uuid4()),
                    "timestamp": "",
                    "level": level,
                    "level_int": lint,
                    "rule_title": match.rule,
                    "computer": file_path.name,
                    "details_raw": f"{description}  [{strings_info}]",
                    "yara_rule": match.rule,
                    "yara_tags": list(match.tags),
                    "yara_strings": strings_info,
                }
            )

    if not results:
        results.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": "",
                "level": "informational",
                "level_int": 1,
                "rule_title": "YARA: No matches",
                "computer": "",
                "details_raw": "No YARA rules matched the submitted files.",
            }
        )

    return results


def _run_yara_cli(
    run_id: str, work_dir: Path, sources_dir: Path, yara_bin: str, params: dict, tool_meta: dict
) -> list[dict]:
    """Fallback: use the yara CLI binary."""
    rules_file = work_dir / "rules.yar"
    rules_file.write_text(_YARA_RULES_SOURCE)

    results: list[dict] = []

    for file_path in sorted(sources_dir.iterdir()):
        if not file_path.is_file():
            continue
        try:
            proc = subprocess.run(
                [yara_bin, "-s", str(rules_file), str(file_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            continue

        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(" ", 1)
            rule = parts[0]
            results.append(
                {
                    "id": str(uuid.uuid4()),
                    "timestamp": "",
                    "level": "medium",
                    "level_int": 3,
                    "rule_title": rule,
                    "computer": file_path.name,
                    "details_raw": line,
                }
            )

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Volatility 3 — memory forensics
# ─────────────────────────────────────────────────────────────────────────────

# Supported memory dump extensions
_MEMORY_EXTS = frozenset(
    {
        ".dmp",
        ".vmem",
        ".raw",
        ".mem",
        ".img",
        ".lime",
        ".dd",
        ".bin",
        ".elf",
        ".e01",
    }
)

# Plugins: (plugin_name, display_label, base_level, max_rows)
_VOL_WIN_PLUGINS = [
    ("windows.pslist.PsList", "Process List", "informational", 500),
    ("windows.cmdline.CmdLine", "Command Lines", "informational", 500),
    ("windows.netscan.NetScan", "Network Connections", "informational", 500),
    ("windows.malfind.Malfind", "Injected Code (Malfind)", "high", 200),
    ("windows.svcscan.SvcScan", "Services", "informational", 400),
    ("windows.dlllist.DllList", "Loaded DLLs", "informational", 300),
    ("windows.registry.hivescan.HiveScan", "Registry Hives", "informational", 200),
]

_VOL_LINUX_PLUGINS = [
    ("linux.pslist.PsList", "Process List", "informational", 500),
    ("linux.bash.Bash", "Bash History", "informational", 300),
    ("linux.netstat.Netstat", "Network Connections", "informational", 500),
    ("linux.lsof.Lsof", "Open Files", "informational", 300),
]


def _find_vol_binary() -> tuple[str, str | None]:
    """
    Return (interpreter, vol_script_or_None).
    Tries: vol3, vol, then common install paths.
    Raises RuntimeError if not found.
    """
    for name in ("vol3", "vol"):
        found = shutil.which(name)
        if found:
            return (found, None)

    # Fallback: look for vol.py in known paths
    candidates = [
        "/opt/volatility3/vol.py",
        "/usr/local/lib/volatility3/vol.py",
        str(Path.home() / "volatility3" / "vol.py"),
    ]
    python3 = shutil.which("python3") or "python3"
    for c in candidates:
        if Path(c).exists():
            return (python3, c)

    raise RuntimeError(
        "Volatility 3 not found in PATH. Install with:\n"
        "  pip install volatility3\n"
        "or place vol3/vol in PATH."
    )


def _run_vol_plugin(
    vol_bin: str,
    vol_script: str | None,
    mem_file: Path,
    plugin: str,
    work_dir: Path,
    tool_meta: dict,
) -> tuple[list[str], list[list]]:
    """
    Run one Volatility 3 plugin with --renderer json.
    Returns (columns, rows) on success, or ([], []) on failure.
    """
    cmd = [vol_bin]
    if vol_script:
        cmd.append(vol_script)
    cmd += ["-f", str(mem_file), "--renderer", "json", plugin]

    tool_meta["log"] += f"  cmd: {' '.join(cmd)}\n"

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 min per plugin
            cwd=str(work_dir),
        )
    except subprocess.TimeoutExpired:
        tool_meta["stdout"] += "  → TIMEOUT (>10 min)\n"
        tool_meta["log"] += f"  [{plugin}] timeout\n"
        return [], []

    stdout = _strip_ansi((proc.stdout or "").strip())
    stderr = _strip_ansi((proc.stderr or "").strip())

    if stderr:
        tool_meta["log"] += f"  stderr: {stderr[:600]}\n"

    if not stdout:
        tool_meta["stdout"] += f"  → no output (code={proc.returncode})\n"
        if stderr:
            tool_meta["stdout"] += f"  {stderr[:200]}\n"
        return [], []

    # Find the JSON object in stdout (Volatility may print progress lines first)
    json_start = stdout.find("{")
    if json_start == -1:
        tool_meta["stdout"] += "  → no JSON found in output\n"
        return [], []

    try:
        data = json.loads(stdout[json_start:])
    except json.JSONDecodeError as exc:
        tool_meta["stdout"] += f"  → JSON decode error: {exc}\n"
        return [], []

    columns = data.get("columns", [])
    rows = data.get("rows", [])
    return columns, rows


def _volatility_rows_to_hits(
    plugin: str,
    label: str,
    base_level: str,
    columns: list[str],
    rows: list[list],
    source_file: str,
) -> list[dict]:
    """Convert Volatility 3 JSON rows into FO hit dicts."""
    col_lower = [c.lower() for c in columns]

    def _col(row: list, *names: str) -> str:
        for name in names:
            try:
                idx = col_lower.index(name.lower())
                v = row[idx]
                return str(v) if v not in (None, "", 0) else ""
            except (ValueError, IndexError):
                pass
        return ""

    results: list[dict] = []
    p_lower = plugin.lower()

    for row in rows:
        if not isinstance(row, list):
            continue

        # Build generic details from all non-empty columns
        parts = [f"{c}: {v}" for c, v in zip(columns, row) if v is not None and v != "" and v != 0]
        details = " | ".join(parts[:15])

        pid = _col(row, "PID", "pid")
        level = base_level
        tags = [f"volatility.{plugin.split('.')[0]}"]

        # Per-plugin rule_title and enrichment
        if "pslist" in p_lower or "pstree" in p_lower:
            name = _col(row, "ImageFileName", "Name", "name")
            ppid = _col(row, "PPID", "ppid")
            title = f"Process: {name or '?'}"
            if pid:
                title += f" (PID {pid})"
            if ppid:
                title += f" ← {ppid}"

        elif "cmdline" in p_lower:
            name = _col(row, "ImageFileName", "Name", "Process")
            args = _col(row, "Args", "CommandLine", "cmdline", "Cmd")
            title = f"CmdLine: {name or '?'}"
            if pid:
                title += f" (PID {pid})"
            details = args or details
            # Flag suspicious patterns
            for pattern in ("encodedcommand", "frombase64", "invoke-expression", "iex(", "bypass"):
                if pattern in (args or "").lower():
                    level = "high"
                    tags.append("suspicious.cmdline")
                    break

        elif "netscan" in p_lower or "netstat" in p_lower:
            proto = _col(row, "Proto", "Type", "proto")
            local = _col(row, "LocalAddr", "LocalIp", "local_addr")
            lport = _col(row, "LocalPort", "lport")
            remote = _col(row, "ForeignAddr", "ForeignIp", "RemoteAddr", "remote_addr")
            rport = _col(row, "ForeignPort", "rport", "RemotePort")
            state = _col(row, "State", "state")
            owner = _col(row, "Owner", "ImageFileName")
            laddr = f"{local}:{lport}" if lport else local
            raddr = f"{remote}:{rport}" if rport else remote
            title = f"Network: {proto} {laddr} → {raddr}"
            if state:
                title += f" [{state}]"
            if owner:
                title += f" ({owner})"

        elif "malfind" in p_lower:
            name = _col(row, "ImageFileName", "Process", "Name")
            protection = _col(row, "Protection", "Vad Tag", "VadTag")
            title = f"Malfind: {name or '?'}"
            if pid:
                title += f" (PID {pid})"
            if protection:
                title += f" [{protection}]"
            level = "high"
            tags.append("malware.injected-code")

        elif "svcscan" in p_lower or "services" in p_lower:
            svc = _col(row, "ServiceName", "Name", "DisplayName")
            state = _col(row, "State", "state")
            start = _col(row, "Start", "StartType")
            title = f"Service: {svc or '?'}"
            if state:
                title += f" [{state}]"
            if start:
                title += f" ({start})"

        elif "dlllist" in p_lower:
            proc = _col(row, "ImageFileName", "Name", "Process")
            path = _col(row, "Path", "FullDllName", "Base")
            title = f"DLL: {proc or '?'} → {Path(path).name if path else '?'}"

        elif "bash" in p_lower:
            cmd = _col(row, "Command", "command", "History")
            uname = _col(row, "Name", "Process", "pid")
            title = f"Bash: {(cmd or '?')[:80]}"
            details = cmd or details

        elif "hive" in p_lower:
            hive = _col(row, "Name", "HiveName", "FileFullPath", "File")
            title = f"Registry Hive: {hive or '?'}"

        elif "lsof" in p_lower:
            proc = _col(row, "Name", "ImageFileName", "pid")
            fpath = _col(row, "File", "Path", "FdType")
            title = f"Open File: {proc or '?'} → {fpath or '?'}"

        else:
            title = label

        try:
            pid_int = int(pid) if pid and str(pid).isdigit() else None
        except (ValueError, TypeError):
            pid_int = None

        results.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": "",
                "level": level,
                "level_int": LEVEL_INT.get(level, 1),
                "rule_title": title[:200],
                "computer": source_file,
                "channel": plugin,
                "event_id": pid_int,
                "details_raw": details[:2000],
                "tags": tags,
            }
        )

    return results


def _run_volatility3(
    run_id: str,
    work_dir: Path,
    sources_dir: Path,
    params: dict,
    tool_meta: dict,
) -> list[dict]:
    """
    Run Volatility 3 memory forensics against an uploaded memory dump.

    Params:
      os:      "windows" (default) | "linux"
      plugins: comma-separated short plugin names to override the default set
               e.g. "pslist,cmdline,malfind"
    """
    vol_bin, vol_script = _find_vol_binary()

    # Find the memory dump — prefer files with known extensions, fall back to largest
    mem_files = [
        p for p in sources_dir.iterdir() if p.is_file() and p.suffix.lower() in _MEMORY_EXTS
    ]
    if not mem_files:
        all_files = [p for p in sources_dir.iterdir() if p.is_file()]
        if not all_files:
            raise RuntimeError("No source files found for Volatility analysis.")
        # Use the largest file as a heuristic for the memory image
        mem_files = sorted(all_files, key=lambda p: p.stat().st_size, reverse=True)[:1]

    mem_file = mem_files[0]
    size_mb = mem_file.stat().st_size / (1024 * 1024)
    logger.info("[%s] Volatility: %s (%.0f MB)", run_id, mem_file.name, size_mb)
    tool_meta["log"] += f"Memory file: {mem_file.name} ({size_mb:.0f} MB)\n"
    tool_meta["stdout"] += (
        f"=== Volatility 3 Memory Forensics ===\n"
        f"File : {mem_file.name}  ({size_mb:.0f} MB)\n"
        f"Tool : {vol_script or vol_bin}\n\n"
    )

    os_hint = (params.get("os") or "windows").lower()
    all_plugins = _VOL_WIN_PLUGINS if os_hint != "linux" else _VOL_LINUX_PLUGINS

    # Allow user to restrict plugins via params
    plugin_filter = [
        p.strip().lower() for p in (params.get("plugins") or "").split(",") if p.strip()
    ]
    if plugin_filter:
        all_plugins = [
            (p, lbl, lvl, mr)
            for p, lbl, lvl, mr in all_plugins
            if any(f in p.lower() for f in plugin_filter)
        ]
        if not all_plugins:
            raise RuntimeError(
                f"No matching plugins for filter {plugin_filter}. "
                f"Available: {[p for p, *_ in (_VOL_WIN_PLUGINS if os_hint != 'linux' else _VOL_LINUX_PLUGINS)]}"
            )

    results: list[dict] = []

    for plugin, label, base_level, max_rows in all_plugins:
        tool_meta["stdout"] += f"\n--- {label} ({plugin}) ---\n"
        tool_meta["log"] += f"\n[{plugin}]\n"

        columns, rows = _run_vol_plugin(vol_bin, vol_script, mem_file, plugin, work_dir, tool_meta)

        if not rows:
            tool_meta["stdout"] += "  0 rows\n"
            continue

        tool_meta["stdout"] += f"  {len(rows):,} rows\n"
        hits = _volatility_rows_to_hits(
            plugin, label, base_level, columns, rows[:max_rows], mem_file.name
        )
        results.extend(hits)
        logger.info("[%s] %s → %d hits", run_id, plugin, len(hits))

    tool_meta["stdout"] += (
        f"\n=== Total: {len(results):,} hits across {len(all_plugins)} plugins ===\n"
    )
    return results


# ─────────────────────────────────────────────────────────────────────────────
# PE Analysis — pefile-based executable inspection
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Strings Analysis — categorised string extraction with IOC identification
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Pattern Search (grep) — regex-based IOC / keyword scanning
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Access Log Analysis
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Cuckoo Sandbox
# ─────────────────────────────────────────────────────────────────────────────


def _run_cuckoo(
    run_id: str, work_dir: Path, sources_dir: Path, params: dict, tool_meta: dict
) -> list[dict]:
    """
    Submit files to a Cuckoo Sandbox instance and collect behavioral reports.
    Requires CUCKOO_API_URL (and optionally CUCKOO_API_TOKEN) env vars.
    """
    import urllib.parse

    # Load config: Redis (UI-configured) first, then env-var fallback.
    # This lets admins set the Cuckoo URL via Settings without touching K8s env vars.
    _redis_cfg: dict = {}
    try:
        _redis_cfg = get_redis().hgetall(_CUCKOO_CONFIG_KEY) or {}
    except Exception:
        pass

    api_url = (_redis_cfg.get("api_url") or os.getenv("CUCKOO_API_URL", "")).rstrip("/")
    api_token = _redis_cfg.get("api_token") or os.getenv("CUCKOO_API_TOKEN", "")

    if not api_url:
        raise RuntimeError(
            "Cuckoo not configured — go to Settings → Integrations → Cuckoo Sandbox "
            "to enter the API URL, or set CUCKOO_API_URL as an environment variable."
        )

    def _cuckoo_req(path: str, method: str = "GET", data=None, files=None):
        """Simple urllib-based Cuckoo API request."""
        url = f"{api_url}{path}"
        headers = {}
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"

        if files:
            # Multipart form — build manually
            boundary = f"----FormBoundary{uuid.uuid4().hex}"
            body_parts: list[bytes] = []
            for field_name, (fname, fdata, ctype) in files.items():
                body_parts.append(
                    f'--{boundary}\r\nContent-Disposition: form-data; name="{field_name}"; '
                    f'filename="{fname}"\r\nContent-Type: {ctype}\r\n\r\n'.encode()
                )
                body_parts.append(fdata if isinstance(fdata, bytes) else fdata.read())
                body_parts.append(b"\r\n")
            body_parts.append(f"--{boundary}--\r\n".encode())
            body = b"".join(body_parts)
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        elif data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
        else:
            req = urllib.request.Request(url, headers=headers, method=method)

        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    results: list[dict] = []

    for file_path in sorted(sources_dir.rglob("*")):
        if not file_path.is_file():
            continue

        tool_meta["stdout"] += f"\n=== Submitting {file_path.name} to Cuckoo ===\n"

        try:
            # Submit file
            with open(file_path, "rb") as fh:
                resp = _cuckoo_req(
                    "/tasks/create/file",
                    method="POST",
                    files={"file": (file_path.name, fh, "application/octet-stream")},
                )
            task_id = resp.get("task_id")
            if not task_id:
                tool_meta["stderr"] += f"No task_id returned for {file_path.name}\n"
                continue

            tool_meta["stdout"] += f"  Task ID: {task_id} — polling for completion…\n"

            # Poll for completion (max 10 min)
            max_wait = 600
            waited = 0
            while waited < max_wait:
                time.sleep(15)
                waited += 15
                status_resp = _cuckoo_req(f"/tasks/view/{task_id}")
                status = (status_resp.get("task") or {}).get("status", "")
                if status == "reported":
                    break
                if status in ("failed_analysis", "failed_processing"):
                    raise RuntimeError(f"Cuckoo task {task_id} failed: {status}")

            # Fetch report
            report = _cuckoo_req(f"/tasks/report/{task_id}")

            # Parse behavioral indicators
            info = report.get("info", {})
            behavior = report.get("behavior", {})
            network = report.get("network", {})
            signatures = report.get("signatures", [])
            score = info.get("score", 0)

            level = (
                "critical"
                if score >= 8
                else ("high" if score >= 5 else "medium" if score >= 3 else "low")
            )

            # One hit per signature detected
            for sig in signatures:
                sig_name = sig.get("name", "Unknown")
                sig_desc = sig.get("description", "")
                sig_severity = sig.get("severity", 1)
                sig_level = (
                    "critical" if sig_severity >= 3 else ("high" if sig_severity == 2 else "medium")
                )
                results.append(
                    {
                        "id": str(uuid.uuid4()),
                        "timestamp": "",
                        "level": sig_level,
                        "level_int": LEVEL_INT.get(sig_level, 2),
                        "rule_title": f"Cuckoo: {sig_name}",
                        "computer": file_path.name,
                        "details_raw": json.dumps(
                            {
                                "description": sig_desc,
                                "file": file_path.name,
                                "task_id": task_id,
                                "score": score,
                            }
                        ),
                        "message": f"{file_path.name} — {sig_desc[:200]}",
                    }
                )

            # Network indicators
            domains = [d.get("domain", "") for d in network.get("domains", [])][:20]
            hosts = [h.get("ip", "") for h in network.get("hosts", [])][:20]
            if domains or hosts:
                results.append(
                    {
                        "id": str(uuid.uuid4()),
                        "timestamp": "",
                        "level": "medium",
                        "level_int": LEVEL_INT["medium"],
                        "rule_title": "Cuckoo: Network Activity",
                        "computer": file_path.name,
                        "details_raw": json.dumps(
                            {"domains": domains, "hosts": hosts, "task_id": task_id}
                        ),
                        "message": f"{file_path.name} — contacted {len(domains)} domain(s), {len(hosts)} host(s)",
                    }
                )

            # Summary hit
            results.append(
                {
                    "id": str(uuid.uuid4()),
                    "timestamp": "",
                    "level": level,
                    "level_int": LEVEL_INT.get(level, 1),
                    "rule_title": f"Cuckoo: Analysis Score {score}/10",
                    "computer": file_path.name,
                    "details_raw": json.dumps(
                        {"score": score, "task_id": task_id, "file": file_path.name}
                    ),
                    "message": f"{file_path.name} — Cuckoo score {score}/10",
                }
            )

            tool_meta["stdout"] += f"  Score: {score}/10 — {len(signatures)} signature(s)\n"

        except Exception as exc:
            tool_meta["stderr"] += f"Cuckoo error for {file_path.name}: {exc}\n"
            results.append(
                {
                    "id": str(uuid.uuid4()),
                    "timestamp": "",
                    "level": "low",
                    "level_int": LEVEL_INT["low"],
                    "rule_title": "Cuckoo: Submission Error",
                    "computer": file_path.name,
                    "details_raw": json.dumps({"error": str(exc), "file": file_path.name}),
                    "message": f"{file_path.name} — {exc}",
                }
            )

    tool_meta["log"] += f"\nCuckoo analysis: {len(results)} findings\n"
    return results


# ─────────────────────────────────────────────────────────────────────────────
# CTI IOC Matching
# ─────────────────────────────────────────────────────────────────────────────

_CTI_IOC_TYPES = ("hash", "ip", "domain", "url", "email", "filename")
_CTI_TYPE_KEY = rk.cti_ioc_type  # callable(ioc_type) → key string

_CTI_MATCH_FIELDS: dict[str, list[str]] = {
    "hash": [
        "process.hash.md5",
        "process.hash.sha1",
        "process.hash.sha256",
        "file.hash.md5",
        "file.hash.sha1",
        "file.hash.sha256",
        "message",
    ],
    "ip": [
        "network.src_ip",
        "network.dst_ip",
        "network.dest_ip",
        "source.ip",
        "destination.ip",
        "message",
    ],
    "domain": ["dns.question.name", "url.domain", "host.hostname", "message"],
    "url": ["url.full", "url.original", "message"],
    "email": ["email.from.address", "email.to.address", "user.email", "message"],
    "filename": ["file.name", "process.executable", "process.name", "message"],
}

_CTI_BATCH_SIZE = 500

# Token extractors for the free-text `message` field. Testing every IOC against
# each message is O(iocs) per event — at ~1M IOCs that pegs a CPU core for the
# whole scan. Instead pull type-shaped candidate tokens out and do O(1) lookups.
_CTI_RX = {
    "ip": re.compile(r"(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]*"),
    "domain": re.compile(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
    "email": re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    "hash": re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b"),
    "filename": re.compile(r"[^\s\\/]+\.[A-Za-z0-9]{1,8}"),
}


def _cti_get_nested(doc: dict, dotted_key: str):
    """Safely traverse a nested dict by dotted key path."""
    parts = dotted_key.split(".")
    cur = doc
    for part in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


# Structured fields per type for aggregation (message excluded — can't aggregate
# free text at scale, and per-event substring scanning is what made this unusable).
_CTI_AGG_FIELDS = {t: [f for f in fields if f != "message"] for t, fields in _CTI_MATCH_FIELDS.items()}
_CTI_AGG_SIZE = 20000


def _cti_es_search(index: str, body: dict, timeout: int = 120) -> dict:
    url = f"{ELASTICSEARCH_URL.rstrip('/')}/{index}/_search"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _cti_terms_agg(index: str, field: str, size: int = _CTI_AGG_SIZE) -> list[tuple]:
    """Distinct values of a structured field + event count + latest event,
    computed server-side (one query, no event scan). Falls back to .keyword.
    Returns [(value, doc_count, {timestamp, host, fo_id}), …]."""
    for fld in (field, f"{field}.keyword"):
        body = {
            "size": 0,
            "aggs": {"v": {
                "terms": {"field": fld, "size": size},
                "aggs": {"latest": {"top_hits": {
                    "size": 1,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "_source": ["timestamp", "host", "fo_id"],
                }}},
            }},
        }
        try:
            resp = _cti_es_search(index, body)
        except Exception:
            continue
        buckets = resp.get("aggregations", {}).get("v", {}).get("buckets")
        if buckets is None:
            continue
        out = []
        for b in buckets:
            key = b.get("key")
            if key is None:
                continue
            hh = b.get("latest", {}).get("hits", {}).get("hits", [])
            src = hh[0].get("_source", {}) if hh else {}
            host = src.get("host", {})
            out.append((str(key), int(b.get("doc_count", 0)), {
                "timestamp": src.get("timestamp", ""),
                "host": host.get("hostname", "") if isinstance(host, dict) else "",
                "fo_id": src.get("fo_id", ""),
            }))
        return out
    return []


def _run_cti_match(
    run_id: str,
    case_id: str,
    work_dir: Path,
    sources_dir: Path,
    params: dict,
    tool_meta: dict,
) -> list[dict]:
    """Match case events against the IOC DB via Elasticsearch aggregations.

    Returns ONE enriched record per distinct indicator present (value, event
    count, latest event, feed/threat metadata) — not one row per matching event.
    At 10M+ events the old per-event scan produced millions of rows and timed
    out; aggregation runs in a handful of queries regardless of event count."""
    r = redis.from_url(REDIS_URL, decode_responses=True)

    # Load all IOCs into memory grouped by type. IOCs are stored as a per-type
    # HASH (value → JSON); older deployments used a SET, so read defensively.
    ioc_sets: dict[str, dict[str, dict]] = {}
    for ioc_type in _CTI_IOC_TYPES:
        type_key = _CTI_TYPE_KEY(ioc_type)
        try:
            ktype = r.type(type_key)
            members = list(r.hvals(type_key)) if ktype == "hash" else (
                list(r.smembers(type_key)) if ktype == "set" else []
            )
        except Exception:
            members = []
        lookup: dict[str, dict] = {}
        for m in members:
            try:
                obj = json.loads(m)
                # Own/private IPs are kept but TAGGED, so the timeline can filter
                # them out — not dropped here (separation, not exclusion).
                val = obj.get("value", "").lower()
                if val:
                    lookup[val] = obj
            except (json.JSONDecodeError, TypeError):
                pass
        if lookup:
            ioc_sets[ioc_type] = lookup

    total_iocs = sum(len(v) for v in ioc_sets.values())
    tool_meta["log"] += f"Loaded {total_iocs} IOC(s) across {len(ioc_sets)} type(s)\n"

    if not ioc_sets:
        tool_meta["stdout"] += "No IOCs loaded — ingest CTI feeds first.\n"
        return []

    index = f"fo-case-{case_id}-*"

    # Optional type narrowing (params.types / params.ioc_types).
    sel_types = list(ioc_sets.keys())
    raw_types = params.get("types") or params.get("ioc_types")
    if raw_types:
        wanted = {t.strip() for t in (raw_types if isinstance(raw_types, list) else str(raw_types).split(","))}
        sel_types = [t for t in sel_types if t in wanted]

    # value_lower -> aggregated indicator
    indicators: dict[str, dict] = {}
    fields_checked = 0
    for ioc_type in sel_types:
        lookup = ioc_sets[ioc_type]
        for field in _CTI_AGG_FIELDS.get(ioc_type, []):
            fields_checked += 1
            for value, count, latest in _cti_terms_agg(index, field):
                obj = lookup.get(value.lower())
                if not obj:
                    continue
                key = f"{ioc_type}:{value.lower()}"
                ind = indicators.get(key)
                if ind:
                    ind["event_count"] += count
                    if latest.get("timestamp", "") > ind["timestamp"]:
                        ind["timestamp"] = latest.get("timestamp", "")
                        ind["computer"] = latest.get("host", "")
                        ind["event_fo_id"] = latest.get("fo_id", "")
                    continue
                is_own = bool(obj.get("is_own"))
                is_private = bool(obj.get("is_private"))
                indicators[key] = {
                    "ioc_type": ioc_type,
                    "ioc_value": obj.get("value", value),
                    "event_count": count,
                    "timestamp": latest.get("timestamp", ""),
                    "computer": latest.get("host", ""),
                    "event_fo_id": latest.get("fo_id", ""),
                    "matched_field": field,
                    "obj": obj,
                    "is_own": is_own,
                    "is_private": is_private,
                    "sev": "info" if (is_own or is_private) else "high",
                }

    results: list[dict] = []
    for ind in indicators.values():
        obj = ind["obj"]
        sev = ind["sev"]
        qualifier = " (own)" if ind["is_own"] else " (private)" if ind["is_private"] else ""
        n = ind["event_count"]
        results.append({
            "id": str(uuid.uuid4()),
            "timestamp": ind["timestamp"],
            "level": sev,
            "level_int": LEVEL_INT.get(sev, 4),
            "rule_title": (
                f"CTI Match{qualifier} — {ind['ioc_type']}: {ind['ioc_value'][:80]} "
                f"({n} event{'s' if n != 1 else ''})"
            ),
            "computer": ind["computer"],
            "details_raw": json.dumps({
                "ioc_type": ind["ioc_type"],
                "ioc_value": ind["ioc_value"],
                "event_count": n,
                "matched_field": ind["matched_field"],
                "indicator_id": obj.get("indicator_id", ""),
                "feed_name": obj.get("feed_name", ""),
                "threat_type": obj.get("threat_type", ""),
                "confidence": obj.get("confidence", ""),
                "tags": obj.get("tags", ""),
                "event_fo_id": ind["event_fo_id"],
                "is_own": ind["is_own"],
                "is_private": ind["is_private"],
            }),
            "event_fo_id": ind["event_fo_id"],
            "ioc_type": ind["ioc_type"],
            "ioc_value": ind["ioc_value"],
            "event_count": n,
            "feed_name": obj.get("feed_name", ""),
            "matched_field": ind["matched_field"],
            "is_own": ind["is_own"],
            "is_private": ind["is_private"],
        })

    real = sum(1 for i in indicators.values() if i["sev"] == "high")
    total_hits = sum(i["event_count"] for i in indicators.values())
    tool_meta["log"] += (
        f"Aggregated {fields_checked} field(s) — {len(results)} distinct indicator(s)\n"
    )
    tool_meta["stdout"] += (
        f"IOCs in DB         : {total_iocs}\n"
        f"Distinct indicators: {len(results)} ({real} external, {len(results) - real} own/private)\n"
        f"Total event hits   : {total_hits}\n"
    )
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Authentication Summary (ES-aggregation triage — brute force / password spray)
# ─────────────────────────────────────────────────────────────────────────────

_AUTH_FAILED_QUERY = {"bool": {"should": [
    {"term": {"evtx.event_id": 4625}},
    {"match_phrase": {"message": "failed password"}},
    {"match_phrase": {"message": "authentication failure"}},
    {"match_phrase": {"message": "failed login"}},
    {"match_phrase": {"message": "invalid user"}},
], "minimum_should_match": 1}}

_AUTH_SUCCESS_QUERY = {"bool": {"should": [
    {"term": {"evtx.event_id": 4624}},
    {"match_phrase": {"message": "accepted password"}},
    {"match_phrase": {"message": "session opened"}},
], "minimum_should_match": 1}}


def _auth_agg(index: str, query: dict, field: str, size: int = 100) -> list[tuple]:
    """Terms aggregation of a field filtered by `query`, with latest event.
    Returns [(value, count, latest_ts, latest_host), …]; falls back to .keyword."""
    for fld in (field, f"{field}.keyword"):
        body = {"size": 0, "query": query, "aggs": {"v": {
            "terms": {"field": fld, "size": size},
            "aggs": {"latest": {"top_hits": {"size": 1,
                "sort": [{"timestamp": {"order": "desc"}}], "_source": ["timestamp", "host"]}}},
        }}}
        try:
            resp = _cti_es_search(index, body)
        except Exception:
            continue
        buckets = resp.get("aggregations", {}).get("v", {}).get("buckets")
        if buckets is None:
            continue
        out = []
        for b in buckets:
            k = b.get("key")
            if k is None or k == "":
                continue
            hh = b.get("latest", {}).get("hits", {}).get("hits", [])
            src = hh[0].get("_source", {}) if hh else {}
            host = src.get("host", {})
            out.append((str(k), int(b.get("doc_count", 0)), src.get("timestamp", ""),
                        host.get("hostname", "") if isinstance(host, dict) else ""))
        return out
    return []


def _auth_total(index: str, query: dict) -> int:
    try:
        resp = _cti_es_search(index, {"size": 0, "track_total_hits": True, "query": query})
        t = resp.get("hits", {}).get("total", {})
        return t.get("value", 0) if isinstance(t, dict) else int(t or 0)
    except Exception:
        return 0


def _run_auth_summary(run_id, case_id, work_dir, sources_dir, params, tool_meta):
    """Aggregate authentication events (Windows 4624/4625 + Linux ssh/PAM) to
    surface brute-force / password-spray — by source IP and by targeted account.
    ES-side aggregation, so it is fast regardless of event volume."""
    index = f"fo-case-{case_id}-*"
    try:
        min_fail = int(params.get("min_failures", 10))
    except Exception:
        min_fail = 10

    by_src = _auth_agg(index, _AUTH_FAILED_QUERY, "network.src_ip")
    by_user = _auth_agg(index, _AUTH_FAILED_QUERY, "user.name")
    total_fail = _auth_total(index, _AUTH_FAILED_QUERY)
    total_ok = _auth_total(index, _AUTH_SUCCESS_QUERY)

    results: list[dict] = []
    for ip, cnt, ts, host in by_src:
        if cnt >= min_fail:
            results.append({
                "id": str(uuid.uuid4()), "timestamp": ts,
                "level": "high", "level_int": LEVEL_INT.get("high", 4),
                "rule_title": f"Possible brute force from {ip} ({cnt} failed logons)",
                "computer": host,
                "details_raw": json.dumps({"source_ip": ip, "failed_count": cnt, "kind": "brute_force_source"}),
            })
    for user, cnt, ts, host in by_user:
        if cnt >= min_fail:
            results.append({
                "id": str(uuid.uuid4()), "timestamp": ts,
                "level": "medium", "level_int": LEVEL_INT.get("medium", 3),
                "rule_title": f"Account targeted: {user} ({cnt} failed logons)",
                "computer": host,
                "details_raw": json.dumps({"user": user, "failed_count": cnt, "kind": "brute_force_user"}),
            })
    results.append({
        "id": str(uuid.uuid4()), "timestamp": "",
        "level": "informational", "level_int": LEVEL_INT.get("informational", 1),
        "rule_title": f"Authentication summary — {total_fail} failed, {total_ok} successful logon(s)",
        "computer": "",
        "details_raw": json.dumps({
            "failed_total": total_fail, "success_total": total_ok,
            "top_failed_sources": [{"ip": i, "count": c} for i, c, _, _ in by_src[:10]],
            "top_failed_users": [{"user": u, "count": c} for u, c, _, _ in by_user[:10]],
            "kind": "summary",
        }),
    })

    bf = sum(1 for r in results if r["level"] in ("high", "medium"))
    tool_meta["log"] += f"Auth summary: {total_fail} failed / {total_ok} ok; {bf} brute-force finding(s)\n"
    tool_meta["stdout"] += (
        f"Failed logons       : {total_fail}\n"
        f"Successful logons   : {total_ok}\n"
        f"Brute-force findings: {bf}\n"
    )
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Browser History Report
# ─────────────────────────────────────────────────────────────────────────────

# Search engine query parameter patterns: (domain_fragment, query_param)
_SEARCH_ENGINES = [
    ("google.", "q"),
    ("bing.com", "q"),
    ("duckduckgo.", "q"),
    ("yahoo.com", "p"),
    ("ecosia.org", "q"),
    ("baidu.com", "wd"),
    ("yandex.", "text"),
    ("search.brave", "q"),
    ("startpage.", "query"),
]

_BROWSER_BATCH = 500


def _extract_domain(url: str) -> str:
    """Return the bare domain (no scheme/www/path) from a URL string."""
    try:
        # Strip scheme
        s = url.split("://", 1)[-1]
        # Strip path/query/fragment
        domain = s.split("/")[0].split("?")[0].split("#")[0]
        # Strip port
        domain = domain.rsplit(":", 1)[0]
        # Strip leading www.
        if domain.startswith("www."):
            domain = domain[4:]
        return domain.lower() or url
    except Exception:
        return url


def _extract_search_query(url: str) -> str | None:
    """Extract the search query string from a known search engine URL, or None."""
    url_lower = url.lower()
    for engine_frag, param in _SEARCH_ENGINES:
        if engine_frag in url_lower:
            # Parse query string manually (no urllib in safe env)
            try:
                qs = url.split("?", 1)[1] if "?" in url else ""
                for kv in qs.split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        if k.lower() == param:
                            # URL-decode + signs and percent-encoding (basic)
                            query = v.replace("+", " ")
                            # Simple percent-decode for common chars
                            import urllib.parse

                            query = urllib.parse.unquote(query)
                            return query.strip() if query.strip() else None
            except Exception:
                pass
    return None


def _run_browser_report(
    run_id: str,
    case_id: str,
    work_dir: Path,
    sources_dir: Path,
    params: dict,
    tool_meta: dict,
) -> list[dict]:
    """
    Generate a browser history report by aggregating all browser events
    already indexed in Elasticsearch for this case.

    Produces hits grouped into:
      1. Summary statistics (one hit)
      2. Top visited domains sorted by visit count
      3. Full URL visit log (sorted by timestamp)
      4. Downloads
      5. Search queries extracted from search engine URLs
      6. Saved login/credential sites
    """
    index = f"fo-case-{case_id}-*"
    query_body: dict = {
        "query": {"term": {"artifact_type": "browser"}},
        "size": _BROWSER_BATCH,
        "sort": [{"_doc": "asc"}],
        "_source": True,
    }

    # Accumulators — one list per browser data_type we want in the report
    visits: list[dict] = []
    downloads: list[dict] = []
    searches: list[dict] = []
    logins: list[dict] = []
    cookies: list[dict] = []
    bookmarks: list[dict] = []
    autofills: list[dict] = []
    formhistory: list[dict] = []
    favicons: list[dict] = []
    events_scanned = 0
    search_after = None
    browsers_seen: set[str] = set()

    while True:
        body = dict(query_body)
        body["sort"] = [{"_doc": "asc"}]
        if search_after:
            body["search_after"] = search_after

        try:
            url_es = f"{ELASTICSEARCH_URL.rstrip('/')}/{index}/_search"
            data = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(
                url_es,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                es_resp = json.loads(resp.read())
        except Exception as exc:
            logger.error("[%s] browser_report ES query failed: %s", run_id, exc)
            tool_meta["stderr"] += f"ES query failed: {exc}\n"
            break

        hits = es_resp.get("hits", {}).get("hits", [])
        if not hits:
            break

        for hit in hits:
            src = hit.get("_source", {})
            browser_dict = src.get("browser", {})
            if not isinstance(browser_dict, dict):
                events_scanned += 1
                continue

            data_type = browser_dict.get("data_type", "")
            browser_type = browser_dict.get("browser_type", "unknown")
            ts = src.get("timestamp", "")
            browsers_seen.add(browser_type)
            events_scanned += 1

            if data_type == "history":
                raw_url = browser_dict.get("url", "")
                title = browser_dict.get("title", "")
                transition = browser_dict.get("transition", "")
                visit_count = browser_dict.get("visit_count", 1)
                domain = _extract_domain(raw_url)
                query = _extract_search_query(raw_url)
                visits.append(
                    {
                        "timestamp": ts,
                        "url": raw_url,
                        "title": title,
                        "domain": domain,
                        "browser_type": browser_type,
                        "transition": transition,
                        "visit_count": visit_count,
                        "last_visit_time": browser_dict.get("last_visit_time", ts),
                        "typed_count": browser_dict.get("typed_count", 0),
                        "hidden": browser_dict.get("hidden", False),
                        "profile": browser_dict.get("profile", ""),
                        "referrer": browser_dict.get("referrer", "")
                        or browser_dict.get("from_visit_url", ""),
                    }
                )
                if query:
                    engine = "unknown"
                    url_lower = raw_url.lower()
                    for eng_frag, _ in _SEARCH_ENGINES:
                        if eng_frag in url_lower:
                            engine = eng_frag.rstrip(".").replace("search.", "").capitalize()
                            break
                    searches.append(
                        {
                            "timestamp": ts,
                            "query": query,
                            "engine": engine,
                            "url": raw_url,
                            "browser_type": browser_type,
                            "profile": browser_dict.get("profile", ""),
                        }
                    )

            elif data_type == "download":
                downloads.append(
                    {
                        "timestamp": ts,
                        "url": browser_dict.get("tab_url", "") or browser_dict.get("url", ""),
                        "referrer": browser_dict.get("referrer", ""),
                        "filename": browser_dict.get("target_path", "")
                        or browser_dict.get("current_path", ""),
                        "size_bytes": browser_dict.get("total_bytes", 0),
                        "received_bytes": browser_dict.get("received_bytes", 0),
                        "mime_type": browser_dict.get("mime_type", ""),
                        "state": browser_dict.get("state", ""),
                        "danger_type": browser_dict.get("danger_type", ""),
                        "interrupt": browser_dict.get("interrupt_reason", ""),
                        "start_time": browser_dict.get("start_time", ts),
                        "end_time": browser_dict.get("end_time", ""),
                        "browser_type": browser_type,
                        "profile": browser_dict.get("profile", ""),
                    }
                )

            elif data_type == "login":
                logins.append(
                    {
                        "timestamp": ts,
                        "url": browser_dict.get("origin_url", "") or browser_dict.get("url", ""),
                        "action_url": browser_dict.get("action_url", ""),
                        "username": browser_dict.get("username_value", ""),
                        "username_field": browser_dict.get("username_element", ""),
                        "password_field": browser_dict.get("password_element", ""),
                        "times_used": browser_dict.get("times_used", 0),
                        "date_created": browser_dict.get("date_created", ts),
                        "date_last_used": browser_dict.get("date_last_used", ""),
                        "blacklisted": browser_dict.get("blacklisted_by_user", False),
                        "browser_type": browser_type,
                        "profile": browser_dict.get("profile", ""),
                    }
                )

            elif data_type == "cookie":
                cookies.append(
                    {
                        "timestamp": ts,
                        "host": browser_dict.get("host_key", "") or browser_dict.get("host", ""),
                        "name": browser_dict.get("name", ""),
                        "value": browser_dict.get("value", ""),
                        "path": browser_dict.get("path", ""),
                        "expires_utc": browser_dict.get("expires_utc", ""),
                        "is_secure": browser_dict.get("is_secure", False),
                        "is_httponly": browser_dict.get("is_httponly", False),
                        "samesite": browser_dict.get("samesite", ""),
                        "browser_type": browser_type,
                        "profile": browser_dict.get("profile", ""),
                    }
                )

            elif data_type == "bookmark":
                bookmarks.append(
                    {
                        "timestamp": ts,
                        "url": browser_dict.get("url", ""),
                        "title": browser_dict.get("title", "") or browser_dict.get("name", ""),
                        "folder": browser_dict.get("folder", "") or browser_dict.get("parent", ""),
                        "date_added": browser_dict.get("date_added", ts),
                        "browser_type": browser_type,
                        "profile": browser_dict.get("profile", ""),
                    }
                )

            elif data_type == "autofill":
                autofills.append(
                    {
                        "timestamp": ts,
                        "name": browser_dict.get("name", ""),
                        "value": browser_dict.get("value", ""),
                        "count": browser_dict.get("count", 0),
                        "date_created": browser_dict.get("date_created", ts),
                        "date_last_used": browser_dict.get("date_last_used", ""),
                        "browser_type": browser_type,
                        "profile": browser_dict.get("profile", ""),
                    }
                )

            elif data_type == "formhistory":
                formhistory.append(
                    {
                        "timestamp": ts,
                        "field_name": browser_dict.get("fieldname", "")
                        or browser_dict.get("name", ""),
                        "value": browser_dict.get("value", ""),
                        "times_used": browser_dict.get("times_used", 0),
                        "first_used": browser_dict.get("first_used", ts),
                        "last_used": browser_dict.get("last_used", ""),
                        "browser_type": browser_type,
                        "profile": browser_dict.get("profile", ""),
                    }
                )

            elif data_type == "favicon":
                favicons.append(
                    {
                        "timestamp": ts,
                        "url": browser_dict.get("page_url", "") or browser_dict.get("url", ""),
                        "icon_url": browser_dict.get("icon_url", ""),
                        "browser_type": browser_type,
                        "profile": browser_dict.get("profile", ""),
                    }
                )

        search_after = hits[-1].get("sort")
        if not search_after:
            break

    # ── Aggregate domain counts ───────────────────────────────────────────────
    domain_counts: dict[str, int] = {}
    for v in visits:
        d = v["domain"]
        domain_counts[d] = domain_counts.get(d, 0) + 1

    top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)

    results: list[dict] = []

    # ── Hit 1: Summary ────────────────────────────────────────────────────────
    summary_lines = [
        f"Browser(s) detected : {', '.join(sorted(browsers_seen)) or 'none'}",
        f"URL visits          : {len(visits)}",
        f"Unique domains      : {len(domain_counts)}",
        f"Downloads           : {len(downloads)}",
        f"Search queries      : {len(searches)}",
        f"Saved logins        : {len(logins)}",
        f"Cookies             : {len(cookies)}",
        f"Bookmarks           : {len(bookmarks)}",
        f"Autofill entries    : {len(autofills)}",
        f"Form history        : {len(formhistory)}",
        f"Favicons            : {len(favicons)}",
    ]
    tool_meta["stdout"] += "\n".join(summary_lines) + "\n"
    tool_meta["log"] += (
        f"Events scanned: {events_scanned} | visits: {len(visits)} | "
        f"domains: {len(domain_counts)} | downloads: {len(downloads)} | "
        f"searches: {len(searches)} | logins: {len(logins)}\n"
    )

    results.append(
        {
            "id": str(uuid.uuid4()),
            "timestamp": "",
            "level": "informational",
            "level_int": LEVEL_INT["informational"],
            "rule_title": "Browser History Summary",
            "details_raw": json.dumps(
                {
                    "browsers": sorted(browsers_seen),
                    "total_visits": len(visits),
                    "unique_domains": len(domain_counts),
                    "downloads": len(downloads),
                    "search_queries": len(searches),
                    "saved_logins": len(logins),
                    "cookies": len(cookies),
                    "bookmarks": len(bookmarks),
                    "autofill": len(autofills),
                    "formhistory": len(formhistory),
                    "favicons": len(favicons),
                }
            ),
            "summary": "\n".join(summary_lines),
            "section": "summary",
        }
    )

    # ── Hits 2+: Top domains ──────────────────────────────────────────────────
    for rank, (domain, count) in enumerate(top_domains[:100], start=1):
        results.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": "",
                "level": "informational",
                "level_int": LEVEL_INT["informational"],
                "rule_title": f"Top Domain #{rank}: {domain} ({count} visit{'s' if count != 1 else ''})",
                "details_raw": json.dumps(
                    {
                        "rank": rank,
                        "domain": domain,
                        "visits": count,
                    }
                ),
                "domain": domain,
                "visits": count,
                "section": "top_domains",
            }
        )

    # ── Hits: Search queries ──────────────────────────────────────────────────
    for sq in searches:
        results.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": sq["timestamp"],
                "level": "informational",
                "level_int": LEVEL_INT["informational"],
                "rule_title": f"Search: {sq['query'][:120]} [{sq['engine']}]",
                "details_raw": json.dumps(sq),
                "query": sq["query"],
                "engine": sq["engine"],
                "section": "searches",
            }
        )

    # ── Hits: Downloads ───────────────────────────────────────────────────────
    for dl in downloads:
        fname = dl["filename"].split("/")[-1].split("\\")[-1] if dl["filename"] else dl["url"]
        size_kb = f"{dl['size_bytes'] // 1024} KB" if dl["size_bytes"] else "unknown size"
        results.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": dl["timestamp"],
                "level": "low",
                "level_int": LEVEL_INT["low"],
                "rule_title": f"Download: {fname} ({size_kb})",
                "details_raw": json.dumps(dl),
                "filename": fname,
                "section": "downloads",
            }
        )

    # ── Hits: Saved logins ────────────────────────────────────────────────────
    for lg in logins:
        results.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": lg["timestamp"],
                "level": "medium",
                "level_int": LEVEL_INT["medium"],
                "rule_title": f"Saved Login: {_extract_domain(lg['url'])} — user: {lg['username'] or '(blank)'}",
                "details_raw": json.dumps(lg),
                "url": lg["url"],
                "username": lg["username"],
                "section": "logins",
            }
        )

    # ── Hits: Full URL visit log (sorted by timestamp) ────────────────────────
    visits_sorted = sorted(visits, key=lambda v: v["timestamp"] or "")
    for v in visits_sorted:
        results.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": v["timestamp"],
                "level": "informational",
                "level_int": LEVEL_INT["informational"],
                "rule_title": f"Visit: {v['title'] or v['url'][:120]}",
                "details_raw": json.dumps(v),
                "url": v["url"],
                "domain": v["domain"],
                "section": "visits",
            }
        )

    # ── Hits: Cookies ─────────────────────────────────────────────────────────
    for ck in cookies:
        results.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": ck["timestamp"],
                "level": "informational",
                "level_int": LEVEL_INT["informational"],
                "rule_title": f"Cookie: {ck['host']} → {ck['name']}",
                "details_raw": json.dumps(ck),
                "host": ck["host"],
                "name": ck["name"],
                "section": "cookies",
            }
        )

    # ── Hits: Bookmarks ───────────────────────────────────────────────────────
    for bk in bookmarks:
        results.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": bk["timestamp"],
                "level": "informational",
                "level_int": LEVEL_INT["informational"],
                "rule_title": f"Bookmark: {bk['title'] or bk['url'][:100]}",
                "details_raw": json.dumps(bk),
                "url": bk["url"],
                "folder": bk["folder"],
                "section": "bookmarks",
            }
        )

    # ── Hits: Autofill ────────────────────────────────────────────────────────
    for af in autofills:
        results.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": af["timestamp"],
                "level": "informational",
                "level_int": LEVEL_INT["informational"],
                "rule_title": f"Autofill: {af['name']} = {af['value'][:80]}",
                "details_raw": json.dumps(af),
                "name": af["name"],
                "value": af["value"],
                "section": "autofill",
            }
        )

    # ── Hits: Form history ────────────────────────────────────────────────────
    for fh in formhistory:
        results.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": fh["timestamp"],
                "level": "informational",
                "level_int": LEVEL_INT["informational"],
                "rule_title": f"Form input: {fh['field_name']} = {str(fh['value'])[:80]}",
                "details_raw": json.dumps(fh),
                "field_name": fh["field_name"],
                "value": fh["value"],
                "section": "formhistory",
            }
        )

    # ── Hits: Favicons ────────────────────────────────────────────────────────
    for fv in favicons:
        results.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": fv["timestamp"],
                "level": "informational",
                "level_int": LEVEL_INT["informational"],
                "rule_title": f"Favicon: {fv['url'][:120]}",
                "details_raw": json.dumps(fv),
                "url": fv["url"],
                "icon_url": fv["icon_url"],
                "section": "favicons",
            }
        )

    logger.info(
        "[%s] browser_report: %d result hits from %d events", run_id, len(results), events_scanned
    )
    return results
