"""
Performance Metrics API.

Each metric section runs in its own thread with a hard wall-clock deadline
so the dashboard endpoint always responds in < 5 s even when a backend
(Celery, MinIO, …) is slow or unreachable.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from datetime import UTC, datetime

import redis_keys as rk
from fastapi import APIRouter

from config import get_redis_with_timeout as _get_redis
from config import settings

router = APIRouter(prefix="/metrics", tags=["metrics"])

# Per-section deadline in seconds.  Total endpoint budget ≈ _SECTION_TIMEOUT + 0.5 s.
_SECTION_TIMEOUT = 1.5


# ── Helpers ───────────────────────────────────────────────────────────────────


def _run_with_timeout(fn, default: dict) -> dict:
    """Execute *fn* in a thread; return *default* on timeout or any error."""
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(fn)
        try:
            return fut.result(timeout=_SECTION_TIMEOUT)
        except (FuturesTimeout, Exception):
            return default


def _get_system_metrics() -> dict:
    """CPU, memory, and disk usage from /proc (container-aware)."""
    result = {
        "cpu_percent": 0.0,
        "memory_used_mb": 0.0,
        "memory_total_mb": 0.0,
        "memory_percent": 0.0,
        "disk_used_gb": 0.0,
        "disk_total_gb": 0.0,
        "disk_percent": 0.0,
    }

    # CPU — two /proc/stat snapshots 100 ms apart
    try:

        def _read_cpu():
            with open("/proc/stat") as f:
                parts = f.readline().split()
            vals = list(map(int, parts[1:9]))
            idle = vals[3] + vals[4]
            return idle, sum(vals)

        idle1, total1 = _read_cpu()
        time.sleep(0.1)
        idle2, total2 = _read_cpu()
        d_total = total2 - total1
        d_idle = idle2 - idle1
        result["cpu_percent"] = round((1 - d_idle / d_total) * 100, 1) if d_total else 0.0
    except Exception:
        try:
            load1, _, _ = os.getloadavg()
            result["cpu_percent"] = round(min(load1 / (os.cpu_count() or 1) * 100, 100), 1)
        except Exception:
            pass

    # Memory — cgroup v2 → cgroup v1 → /proc/meminfo
    try:
        mem_total = None
        mem_used = None
        for cur_path, lim_path in [
            ("/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.max"),
            (
                "/sys/fs/cgroup/memory/memory.usage_in_bytes",
                "/sys/fs/cgroup/memory/memory.limit_in_bytes",
            ),
        ]:
            if os.path.exists(cur_path):
                with open(cur_path) as f:
                    mem_used = int(f.read().strip())
                with open(lim_path) as f:
                    val = f.read().strip()
                    mem_total = int(val) if val != "max" else None
                break

        if mem_total is None or mem_total > 2**60:
            with open("/proc/meminfo") as f:
                info = {}
                for line in f:
                    parts = line.split()
                    info[parts[0].rstrip(":")] = int(parts[1]) * 1024
                mem_total = info.get("MemTotal", 0)
                mem_used = mem_total - info.get("MemAvailable", 0)

        if mem_total:
            result["memory_total_mb"] = round(mem_total / (1024 * 1024), 1)
            result["memory_used_mb"] = round((mem_used or 0) / (1024 * 1024), 1)
            result["memory_percent"] = round((mem_used or 0) / mem_total * 100, 1)
    except Exception:
        pass

    # Disk
    try:
        st = os.statvfs("/")
        total = st.f_frsize * st.f_blocks
        free = st.f_frsize * st.f_bavail
        used = total - free
        result["disk_total_gb"] = round(total / (1024**3), 2)
        result["disk_used_gb"] = round(used / (1024**3), 2)
        result["disk_percent"] = round(used / total * 100, 1) if total else 0.0
    except Exception:
        pass

    return result


def _parse_es_size(size_str: str) -> float:
    if not size_str:
        return 0.0
    s = str(size_str).strip().lower()
    for suffix, mult in [("tb", 1024**4), ("gb", 1024**3), ("mb", 1024**2), ("kb", 1024), ("b", 1)]:
        if s.endswith(suffix):
            try:
                return float(s[: -len(suffix)]) * mult
            except ValueError:
                return 0.0
    try:
        return float(s)
    except ValueError:
        return 0.0


def _get_elasticsearch_metrics() -> dict:
    """Cluster health + index stats; hard 3 s timeout per request."""
    result = {
        "status": "unavailable",
        "node_count": 0,
        "total_docs": 0,
        "total_size_mb": 0.0,
        "indices": [],
        "jvm_heap_pct": None,
        "indexing_total": None,
        "search_total": None,
        "query_latency_ms": None,
        "active_shards": None,
        "unassigned_shards": None,
    }
    base = settings.ELASTICSEARCH_URL
    try:
        with urllib.request.urlopen(
            urllib.request.Request(f"{base}/_cluster/health"), timeout=3
        ) as resp:
            health = json.loads(resp.read())
        result["status"] = health.get("status", "unknown")
        result["node_count"] = health.get("number_of_nodes", 0)
        result["active_shards"] = health.get("active_shards", 0)
        result["unassigned_shards"] = health.get("unassigned_shards", 0)
    except Exception:
        return result

    # Node stats — JVM heap pressure + cumulative indexing/search counters.
    try:
        with urllib.request.urlopen(
            urllib.request.Request(f"{base}/_nodes/stats/jvm,indices"), timeout=3
        ) as resp:
            ns = json.loads(resp.read())
        nodes = list((ns.get("nodes") or {}).values())
        if nodes:
            heaps = [n.get("jvm", {}).get("mem", {}).get("heap_used_percent") for n in nodes]
            heaps = [h for h in heaps if isinstance(h, (int, float))]
            if heaps:
                result["jvm_heap_pct"] = round(sum(heaps) / len(heaps), 1)
            idx_total = sum(n.get("indices", {}).get("indexing", {}).get("index_total", 0) for n in nodes)
            srch_total = sum(n.get("indices", {}).get("search", {}).get("query_total", 0) for n in nodes)
            srch_ms = sum(n.get("indices", {}).get("search", {}).get("query_time_in_millis", 0) for n in nodes)
            result["indexing_total"] = idx_total
            result["search_total"] = srch_total
            result["query_latency_ms"] = round(srch_ms / srch_total, 2) if srch_total else 0.0
    except Exception:
        pass

    try:
        with urllib.request.urlopen(
            urllib.request.Request(f"{base}/_cat/indices?format=json"), timeout=3
        ) as resp:
            indices = json.loads(resp.read())
        total_docs = 0
        total_size = 0.0
        idx_list = []
        for idx in indices:
            name = idx.get("index", "")
            docs = int(idx.get("docs.count", 0) or 0)
            size_mb = round(_parse_es_size(idx.get("store.size", "0")) / (1024 * 1024), 2)
            total_docs += docs
            total_size += size_mb
            idx_list.append({"name": name, "docs": docs, "size_mb": size_mb})
        result["total_docs"] = total_docs
        result["total_size_mb"] = round(total_size, 2)
        result["indices"] = idx_list
    except Exception:
        pass

    return result


def _get_redis_metrics() -> dict:
    result = {
        "used_memory_mb": 0.0,
        "connected_clients": 0,
        "total_keys": 0,
        "uptime_seconds": 0,
        "ops_per_sec": None,
        "hit_rate_pct": None,
        "evicted_keys": None,
        "expired_keys": None,
    }
    try:
        r = _get_redis()
        info = r.info()
        result["used_memory_mb"] = round(info.get("used_memory", 0) / (1024 * 1024), 2)
        result["connected_clients"] = info.get("connected_clients", 0)
        result["uptime_seconds"] = info.get("uptime_in_seconds", 0)
        result["ops_per_sec"] = info.get("instantaneous_ops_per_sec", 0)
        result["evicted_keys"] = info.get("evicted_keys", 0)
        result["expired_keys"] = info.get("expired_keys", 0)
        hits = info.get("keyspace_hits", 0)
        misses = info.get("keyspace_misses", 0)
        if hits + misses > 0:
            result["hit_rate_pct"] = round(100 * hits / (hits + misses), 1)
        total_keys = 0
        for key, val in info.items():
            if isinstance(key, str) and key.startswith("db") and isinstance(val, dict):
                total_keys += val.get("keys", 0)
        result["total_keys"] = total_keys
    except Exception:
        pass
    return result


def _get_minio_metrics() -> dict:
    """Bucket count + quick size estimate (no recursive listing)."""
    result = {
        "bucket_count": 0,
        "total_objects": 0,
        "total_size_mb": 0.0,
    }
    try:
        from services.storage import get_minio

        client = get_minio()
        buckets = client.list_buckets()
        result["bucket_count"] = len(buckets)

        # Only peek at the first 200 objects total to avoid multi-second scans
        total_objects = 0
        total_size = 0
        OBJECT_LIMIT = 200
        for bucket in buckets:
            for obj in client.list_objects(bucket.name, recursive=False):
                if total_objects >= OBJECT_LIMIT:
                    break
                total_objects += 1
                total_size += obj.size or 0
            if total_objects >= OBJECT_LIMIT:
                break
        result["total_objects"] = total_objects
        result["total_size_mb"] = round(total_size / (1024 * 1024), 2)
    except Exception:
        pass
    return result


def _get_celery_metrics() -> dict:
    result = {
        "active_tasks": 0,
        "reserved_tasks": 0,
        "registered_workers": 0,
        "queue_lengths": {"ingest": 0, "modules": 0, "default": 0},
    }

    # Worker inspection — short timeout so this doesn't stall
    try:
        from celery import Celery as _Celery

        app = _Celery(broker=settings.REDIS_URL)
        inspector = app.control.inspect(timeout=1.5)
        active = inspector.active() or {}
        result["registered_workers"] = len(active)
        result["active_tasks"] = sum(len(t) for t in active.values())
        reserved = inspector.reserved() or {}
        result["reserved_tasks"] = sum(len(t) for t in reserved.values())
    except Exception:
        pass

    # Queue depths via Redis LLEN (fast)
    try:
        r = _get_redis()
        for q in ("ingest", "modules", "default"):
            try:
                result["queue_lengths"][q] = r.llen(q) or 0
            except Exception:
                pass
    except Exception:
        pass

    return result


def _get_cases_metrics() -> dict:
    result = {
        "total_cases": 0,
        "total_jobs": 0,
        "active_jobs": 0,
        "failed_jobs": 0,
    }
    try:
        r = _get_redis()
        result["total_cases"] = r.scard("cases:all") or 0

        total_jobs = active_jobs = failed_jobs = 0
        cursor = 0
        scanned = 0
        while True:
            cursor, keys = r.scan(cursor, match="job:*", count=100)
            for key in keys:
                if scanned >= 1000:
                    break
                scanned += 1
                total_jobs += 1
                try:
                    raw = r.get(key)
                    if raw:
                        job = json.loads(raw)
                        status = job.get("status", "")
                        if status in ("running", "pending"):
                            active_jobs += 1
                        elif status == "failed":
                            failed_jobs += 1
                except Exception:
                    pass
            if cursor == 0 or scanned >= 1000:
                break

        result["total_jobs"] = total_jobs
        result["active_jobs"] = active_jobs
        result["failed_jobs"] = failed_jobs
    except Exception:
        pass
    return result


# ── Defaults returned when a section times out ────────────────────────────────

_DEFAULT_SYSTEM = {
    "cpu_percent": 0.0,
    "memory_used_mb": 0.0,
    "memory_total_mb": 0.0,
    "memory_percent": 0.0,
    "disk_used_gb": 0.0,
    "disk_total_gb": 0.0,
    "disk_percent": 0.0,
}
_DEFAULT_ES = {
    "status": "unavailable",
    "node_count": 0,
    "total_docs": 0,
    "total_size_mb": 0.0,
    "indices": [],
}
_DEFAULT_REDIS = {
    "used_memory_mb": 0.0,
    "connected_clients": 0,
    "total_keys": 0,
    "uptime_seconds": 0,
}
_DEFAULT_MINIO = {"bucket_count": 0, "total_objects": 0, "total_size_mb": 0.0}
_DEFAULT_CELERY = {
    "active_tasks": 0,
    "reserved_tasks": 0,
    "registered_workers": 0,
    "queue_lengths": {"ingest": 0, "modules": 0, "default": 0},
}
_DEFAULT_CASES = {"total_cases": 0, "total_jobs": 0, "active_jobs": 0, "failed_jobs": 0}


def _get_api_metrics() -> dict:
    """Read the rolling request window collected by the telemetry middleware in main.py."""
    result = {
        "total_requests": 0,
        "total_errors": 0,
        "rps": 0.0,
        "p50_ms": None,
        "p95_ms": None,
        "p99_ms": None,
        "error_rate_pct": 0.0,
    }
    try:
        # Import the module-level deque from main
        import main as _main

        window = list(_main._REQUEST_WINDOW)
        totals = _main._REQUEST_TOTALS
        result["total_requests"] = totals.get("count", 0)
        result["total_errors"] = totals.get("errors", 0)
        if window:
            durations = [d for d, _ in window]
            durations.sort()
            n = len(durations)
            result["p50_ms"] = round(durations[int(n * 0.50)], 1)
            result["p95_ms"] = round(durations[min(int(n * 0.95), n - 1)], 1)
            result["p99_ms"] = round(durations[min(int(n * 0.99), n - 1)], 1)
            err_count = sum(1 for _, s in window if s >= 500)
            result["error_rate_pct"] = round(err_count / n * 100, 1)
            # RPS: count requests in the last 60 seconds (assume window covers last ~60 s at typical traffic)
            result["rps"] = round(len(window) / 60, 2)
    except Exception:
        pass
    return result


_DEFAULT_API = {
    "total_requests": 0,
    "total_errors": 0,
    "rps": 0.0,
    "p50_ms": None,
    "p95_ms": None,
    "p99_ms": None,
    "error_rate_pct": 0.0,
}


# ── Endpoint ──────────────────────────────────────────────────────────────────


@router.get("/dashboard")
def metrics_dashboard():
    """
    Return comprehensive real-time metrics from all services.
    Each section runs with a hard timeout so the endpoint always responds
    within a few seconds even when backends are slow or down.
    """
    # Run all sections in parallel, each with its own deadline.
    # NOTE: we must NOT use `with ThreadPoolExecutor(...) as pool:` here because
    # the context-manager calls shutdown(wait=True) on exit — which blocks until
    # every thread finishes even after its future has already timed out.  Instead
    # we collect results first, then shut the pool down in the background so slow
    # threads (e.g. Celery inspector waiting for broker broadcast) can't stall the
    # HTTP response.
    pool = ThreadPoolExecutor(max_workers=7)
    f_system = pool.submit(_get_system_metrics)
    f_es = pool.submit(_get_elasticsearch_metrics)
    f_redis = pool.submit(_get_redis_metrics)
    f_minio = pool.submit(_get_minio_metrics)
    f_celery = pool.submit(_get_celery_metrics)
    f_cases = pool.submit(_get_cases_metrics)
    f_api = pool.submit(_get_api_metrics)

    def _get(fut, default):
        try:
            return fut.result(timeout=_SECTION_TIMEOUT)
        except Exception:
            return default

    result = {
        "timestamp": datetime.now(UTC).isoformat(),
        "system": _get(f_system, _DEFAULT_SYSTEM),
        "elasticsearch": _get(f_es, _DEFAULT_ES),
        "redis": _get(f_redis, _DEFAULT_REDIS),
        "minio": _get(f_minio, _DEFAULT_MINIO),
        "celery": _get(f_celery, _DEFAULT_CELERY),
        "cases": _get(f_cases, _DEFAULT_CASES),
        "api": _get(f_api, _DEFAULT_API),
    }
    # Let any still-running threads finish in the background — don't block.
    pool.shutdown(wait=False)
    return result


# ── Time-series history ────────────────────────────────────────────────────────

_HISTORY_KEY = rk.METRICS_HISTORY
_HISTORY_MAX = 2880  # 24 h at 30 s intervals


def _slim_snapshot() -> dict:
    """
    Collect a compact snapshot for the history buffer.
    Runs in a background asyncio task every 30 s — fast, non-blocking sections only.
    """
    ts = datetime.now(UTC).isoformat()
    sys = _run_with_timeout(_get_system_metrics, _DEFAULT_SYSTEM)
    cel = _run_with_timeout(_get_celery_metrics, _DEFAULT_CELERY)
    cas = _run_with_timeout(_get_cases_metrics, _DEFAULT_CASES)

    # API metrics come from in-process memory — instant
    api = _get_api_metrics()

    snap: dict = {"ts": ts}

    # System
    snap["cpu"] = sys.get("cpu_percent", 0)
    snap["mem"] = sys.get("memory_percent", 0)
    snap["disk"] = sys.get("disk_percent", 0)

    # Celery queues
    ql = cel.get("queue_lengths") or {}
    snap["q_ingest"] = ql.get("ingest", 0)
    snap["q_modules"] = ql.get("modules", 0)
    snap["active"] = cel.get("active_tasks", 0)

    # Jobs
    snap["job_active"] = cas.get("active_jobs", 0)
    snap["job_failed"] = cas.get("failed_jobs", 0)

    # API latency
    snap["p50"] = api.get("p50_ms")
    snap["p95"] = api.get("p95_ms")
    snap["rps"] = api.get("rps", 0)

    return snap


def store_metrics_snapshot() -> None:
    """Write one slim snapshot to the Redis circular buffer. Called by the background task."""
    try:
        r = _get_redis()
        snap = _slim_snapshot()
        r.rpush(_HISTORY_KEY, json.dumps(snap))
        r.ltrim(_HISTORY_KEY, -_HISTORY_MAX, -1)  # keep only the last _HISTORY_MAX entries
    except Exception:
        pass  # Never crash the background loop


@router.get("/history")
def metrics_history(limit: int = 480):
    """
    Return up to *limit* historical metric snapshots (default = 8 h at 30 s).
    Ordered oldest → newest.
    """
    limit = max(1, min(limit, _HISTORY_MAX))
    try:
        r = _get_redis()
        raw = r.lrange(_HISTORY_KEY, -limit, -1)
        snapshots = []
        for item in raw:
            try:
                snapshots.append(json.loads(item))
            except Exception:
                pass
        return {"snapshots": snapshots, "count": len(snapshots)}
    except Exception:
        return {"snapshots": [], "count": 0}
