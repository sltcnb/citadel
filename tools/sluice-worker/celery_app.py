"""Celery application factory."""

import os

from celery import Celery
from kombu import Exchange, Queue

REDIS_URL = os.getenv("REDIS_URL", "redis://redis-service:6379/0")

# Observability: structured JSON logs to stdout + a capped Redis stream the
# admin log viewer reads (citadel:logs:processor). Best-effort — never fatal.
try:
    import observability as _obs
    import redis as _redis

    _obs.setup_json_logging()
    if os.getenv("CITADEL_LOG_TO_REDIS", "true").lower() != "false":
        _rc = _redis.Redis.from_url(REDIS_URL, decode_responses=True)
        _obs.attach_redis_logs("processor", _rc)
        # Mirror the cross-tool orchestration logger to the shared "tools"
        # channel so the worker's bus emits show alongside the API's in one place.
        import logging as _lg

        from citadel_contracts.logship import RedisLogHandler as _RLH

        _tl = _lg.getLogger("citadel.tools")
        if not any(isinstance(h, _RLH) for h in _tl.handlers):
            _tl.addHandler(_RLH("tools", _rc))
        _tl.setLevel(_lg.INFO)
except Exception:  # missing dep / redis down must not stop the worker booting
    pass

# ── Queue definitions ─────────────────────────────────────────────────────────
# ingest   — I/O-bound file parsing; run with higher concurrency
# modules  — CPU/memory-bound analysis binaries; run with lower concurrency
# default  — fallback for any unrouted tasks
_default_exchange = Exchange("forensics", type="direct")

app = Celery(
    "forensics_processor",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["tasks.ingest_task", "tasks.module_task", "tasks.harvest_task"],
)

app.conf.update(
    # ── Serialization ──────────────────────────────────────────────────────
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_compression="gzip",  # compress task payloads in Redis broker
    result_compression="gzip",  # compress result payloads in Redis backend
    timezone="UTC",
    enable_utc=True,
    # ── Reliability ────────────────────────────────────────────────────────
    task_track_started=True,
    task_acks_late=True,  # re-queue on worker crash
    task_reject_on_worker_lost=True,  # requeue if worker disappears mid-task
    worker_prefetch_multiplier=1,  # one task at a time per worker slot
    # ── Time limits ────────────────────────────────────────────────────────
    task_soft_time_limit=3600,  # raise SoftTimeLimitExceeded at 1 h
    task_time_limit=7200,  # SIGKILL at 2 h
    result_expires=604800,  # keep results 7 days
    # ── Memory / stability ─────────────────────────────────────────────────
    # Recycle worker processes after N tasks to prevent memory bloat from
    # large forensic file processing (EVTX, MFT, registry hives).
    worker_max_tasks_per_child=int(os.getenv("WORKER_MAX_TASKS", "50")),
    # ── Queues & routing ───────────────────────────────────────────────────
    task_queues=(
        Queue("ingest", _default_exchange, routing_key="ingest"),
        Queue("modules", _default_exchange, routing_key="modules"),
        Queue("default", _default_exchange, routing_key="default"),
    ),
    task_default_queue="default",
    task_default_exchange="forensics",
    task_default_routing_key="default",
    task_routes={
        # All ingest.* tasks → ingest queue (I/O-bound: MinIO + Elasticsearch)
        "ingest.*": {"queue": "ingest", "routing_key": "ingest"},
        # All module.* tasks → modules queue (CPU-bound: hayabusa, YARA, etc.)
        "module.*": {"queue": "modules", "routing_key": "modules"},
        # harvest.* tasks → modules queue (pytsk3 image traversal is CPU-bound)
        "harvest.*": {"queue": "modules", "routing_key": "modules"},
    },
    # ── Broker connection tuning ───────────────────────────────────────────
    broker_transport_options={
        "visibility_timeout": 7200,  # match hard time limit
        "socket_keepalive": True,
        "retry_policy": {
            "timeout": 5.0,
        },
    },
    broker_connection_retry_on_startup=True,
)

if __name__ == "__main__":
    app.start()
