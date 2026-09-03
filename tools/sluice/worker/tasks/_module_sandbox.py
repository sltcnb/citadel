"""
Sandboxed custom-module runner.

This script is executed as a *child subprocess* by module_task.py so that
custom Python modules written in the Studio editor run in an isolated process.

Security measures applied BEFORE any module code is loaded:
  • resource.setrlimit — caps CPU time, virtual memory, file-write size, and
    number of child processes the module may spawn
  • Home directory remapped to work_dir (no access to /root or /app secrets)
  • stdin consumed (module code cannot read further from stdin)
  • Sensitive environment variables stripped from os.environ

The module receives a rich, documented API:
  run(run_id, case_id, source_files, params, minio_client, redis_client, tmp_dir) -> list | dict

Results are written to stdout as newline-delimited JSON.
All diagnostic output should go to stderr (visible in tool_log in the UI).
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

# ── Read arguments from stdin before stripping anything ───────────────────────
_raw_args = sys.stdin.buffer.read()
args: dict = json.loads(_raw_args)

# ── Strip sensitive environment variables ─────────────────────────────────────
_KEEP_VARS = {"PATH", "HOME", "LANG", "LC_ALL", "PYTHONPATH", "LD_LIBRARY_PATH", "MINIO_BUCKET"}
for _var in list(os.environ.keys()):
    if _var not in _KEEP_VARS:
        del os.environ[_var]

# Remap HOME so the module cannot accidentally read ~/.ssh, ~/.aws, etc.
os.environ["HOME"] = args.get("work_dir", "/tmp")

# ── Apply resource limits (Linux only) ───────────────────────────────────────
try:
    import resource as _resource

    _CPU_SEC = int(args.get("limit_cpu_seconds", 3600))  # aggregate CPU; 0 = off
    _MEM_BYTES = int(args.get("limit_memory_bytes", 8 * 1024**3))  # 8 GB virtual; 0 = off
    _FSIZE = int(args.get("limit_fsize_bytes", 20 * 1024**3))  # 20 GB writes (was 500 MB)

    # Each cap applied only when > 0. RLIMIT_NPROC is NOT applied: it caps
    # processes for the whole shared UID (not this subtree), so in the multi-
    # threaded worker container it made even a single result thread fail with
    # "can't start new thread". Fork-bomb protection belongs at the pod cgroup
    # (pids.max), not a per-UID rlimit.
    if _CPU_SEC > 0:
        _resource.setrlimit(_resource.RLIMIT_CPU, (_CPU_SEC, _CPU_SEC + 60))
    if _MEM_BYTES > 0:
        try:
            _resource.setrlimit(_resource.RLIMIT_AS, (_MEM_BYTES, _MEM_BYTES))
        except (ValueError, OSError):
            pass
    if _FSIZE > 0:
        _resource.setrlimit(_resource.RLIMIT_FSIZE, (_FSIZE, _FSIZE))
    print(
        f"[sandbox] limits set: cpu={_CPU_SEC}s mem={_MEM_BYTES // 1024 // 1024}MB "
        f"fsize={_FSIZE // 1024 // 1024}MB (nproc: cgroup-enforced)",
        file=sys.stderr,
    )
except ImportError:
    print("[sandbox] resource module not available (non-Linux) — limits skipped", file=sys.stderr)
except Exception as _exc:
    print(f"[sandbox] warning: could not set resource limits: {_exc}", file=sys.stderr)

# ── Close stdin so module code cannot read it ─────────────────────────────────
try:
    sys.stdin.close()
    os.close(0)
except Exception:
    pass

# ── Build clients ─────────────────────────────────────────────────────────────
try:
    from minio import Minio as _Minio

    minio_client = _Minio(
        args["minio_endpoint"],
        access_key=args["minio_access"],
        secret_key=args["minio_secret"],
        # Inherited from the parent worker's MINIO_SECURE (secure by
        # default); the sandbox never silently downgrades the transport.
        secure=bool(args.get("minio_secure", True)),
    )
except Exception as _exc:
    print(f"[sandbox] MinIO client init failed: {_exc}", file=sys.stderr)
    minio_client = None

try:
    import redis as _redis_lib

    redis_client = _redis_lib.Redis.from_url(args["redis_url"], decode_responses=True)
except Exception as _exc:
    print(f"[sandbox] Redis client init failed: {_exc}", file=sys.stderr)
    redis_client = None

# ── Load module file ──────────────────────────────────────────────────────────
module_file = Path(args["module_file"])
if not module_file.exists():
    print(json.dumps({"error": f"Module file not found: {module_file}"}))
    sys.exit(1)

try:
    spec = importlib.util.spec_from_file_location("_fo_custom_module", module_file)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot create module spec")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
except Exception as _exc:
    print(json.dumps({"error": f"Module load failed: {_exc}"}))
    sys.exit(1)

run_fn = getattr(mod, "run", None)
if not callable(run_fn):
    print(json.dumps({"error": "Module has no run() function"}))
    sys.exit(1)

# ── Execute ───────────────────────────────────────────────────────────────────
try:
    result = run_fn(
        run_id=args["run_id"],
        case_id=args["case_id"],
        source_files=args["source_files"],
        params=args["params"],
        minio_client=minio_client,
        redis_client=redis_client,
        tmp_dir=Path(args["work_dir"]),
    )
except Exception as _exc:
    import traceback

    print(f"[sandbox] run() raised: {_exc}\n{traceback.format_exc()}", file=sys.stderr)
    print(json.dumps({"error": str(_exc)}))
    sys.exit(1)

# ── Normalise result ──────────────────────────────────────────────────────────
artifacts = []
metrics = {}
status = "ok"
if isinstance(result, list):
    hits = result
elif isinstance(result, dict):
    hits = result.get("hits", [])
    # Pass the structured Result envelope through: artifacts/metrics/status are
    # produced by typed BaseModule analyzers (Result.to_dict) and were being
    # silently dropped here.
    artifacts = [a for a in (result.get("artifacts") or []) if isinstance(a, dict)]
    metrics = result.get("metrics") or {}
    status = result.get("status", "ok")
else:
    hits = []

# Ensure every hit is a dict (drop malformed entries)
hits = [h for h in hits if isinstance(h, dict)]

print(json.dumps({"hits": hits, "artifacts": artifacts, "metrics": metrics, "status": status}))
sys.exit(0)
