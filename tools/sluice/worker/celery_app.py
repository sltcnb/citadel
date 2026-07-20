"""Celery application factory."""

import os

from celery import Celery
from citadel_contracts import redis_url_with_auth
from kombu import Exchange, Queue

# Fold REDIS_PASSWORD into the URL so the Celery broker/backend and every
# from_url() client authenticates against a --requirepass Redis.
REDIS_URL = redis_url_with_auth(os.getenv("REDIS_URL", "redis://redis-service:6379/0"))

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
#
# ingest_high / modules_high — the "_high" twin of each base queue. The API's
# services/celery_dispatch.py pushes analyst-triggered work (module + harvest
# runs) here by default, while bulk background ingest stays on the base
# queue. Priority is enforced purely by *worker subscription order*: the
# Dockerfile's `celery worker -Q ...` lists every *_high queue before its base
# queue, and Kombu's redis transport issues one BLPOP/BRPOP across all
# subscribed keys in that order — Redis always returns from the first
# non-empty key, so a high queue drains ahead of its base queue whenever both
# have work. No custom scheduler needed.
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
    # Backpressure: prefetch how many messages each worker slot buffers ahead of
    # processing. Kept at 1 by default so a burst of dispatches can't pile heavy
    # tasks into a single worker's memory. See robustness.MAX_IN_FLIGHT for the
    # fleet-wide in-flight cap enforced inside the ingest task itself.
    worker_prefetch_multiplier=int(os.getenv("WORKER_PREFETCH_MULTIPLIER", "1")),
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
        Queue("ingest_high", _default_exchange, routing_key="ingest_high"),
        Queue("modules_high", _default_exchange, routing_key="modules_high"),
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
