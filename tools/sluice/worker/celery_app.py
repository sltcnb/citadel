"""Celery application factory."""

import logging
import os

from celery import Celery
from citadel_contracts import redis_url_with_auth
from kombu import Exchange, Queue

# Fold REDIS_PASSWORD into the URL so the Celery broker/backend and every
# from_url() client authenticates against a --requirepass Redis.
REDIS_URL = redis_url_with_auth(os.getenv("REDIS_URL", "redis://redis-service:6379/0"))

logger = logging.getLogger(__name__)

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

# ── Durable telemetry ─────────────────────────────────────────────────────────
# The Redis log stream above is a live tail capped at 2 000 lines — on a busy
# ingest it holds minutes. Telemetry writes every task outcome to Elasticsearch
# instead, so "which parser fails, on what, and how slowly" is still answerable
# a week later. Best-effort: no ES, no telemetry, no impact on the worker.
try:
    from citadel_contracts.telemetry import init_telemetry as _init_telemetry

    _TELEMETRY = _init_telemetry("processor")
    # The worker does NOT install the index template. The mapping is built from
    # every component's telemetry advertisement, and only the API aggregates
    # those; a worker installing a template from its own partial view would
    # race the API and drop the other components' fields. The worker just ships.
except Exception:  # noqa: BLE001
    pass


# ── Task lifecycle telemetry ──────────────────────────────────────────────────
# One event per task, recorded from Celery's own signals rather than sprinkled
# through the task bodies — so a new task type is covered the day it is added,
# and no task can forget to report that it failed.
_TASK_STARTS: dict = {}


def _task_queue(task) -> str:
    try:
        return (getattr(task, "request", None).delivery_info or {}).get("routing_key", "") or ""
    except Exception:  # noqa: BLE001
        return ""


# Positional index of `case_id` per task, resolved from the signature once.
# It is NOT a fixed position — process_artifact/run_module/run_harvest take
# (job_or_run_id, case_id, …) while maybe_run_detections takes (case_id, …), so
# assuming args[0] would silently file every parse under a job id.
_CASE_ARG_INDEX: dict = {}


def _case_arg_index(task) -> int:
    name = getattr(task, "name", "")
    if name in _CASE_ARG_INDEX:
        return _CASE_ARG_INDEX[name]
    idx = -1
    try:
        import inspect

        params = list(inspect.signature(task.run).parameters)
        if params and params[0] == "self":  # bind=True — celery binds it, args don't carry it
            params = params[1:]
        idx = params.index("case_id")
    except Exception:  # noqa: BLE001 — unknown signature just means no case attribution
        idx = -1
    _CASE_ARG_INDEX[name] = idx
    return idx


def _case_id_of(task, kwargs: dict | None, args: tuple | None) -> str:
    """The case a task belongs to, from its kwargs or its positional args."""
    if kwargs and isinstance(kwargs.get("case_id"), str):
        return kwargs["case_id"]
    idx = _case_arg_index(task)
    if idx >= 0 and args and idx < len(args) and isinstance(args[idx], str):
        return args[idx]
    return ""


try:
    import time as _time

    from celery import signals as _signals

    @_signals.task_prerun.connect(weak=False)
    def _telemetry_task_prerun(task_id=None, **_kw):  # noqa: ANN001
        _TASK_STARTS[task_id] = _time.perf_counter()

    @_signals.task_postrun.connect(weak=False)
    def _telemetry_task_postrun(  # noqa: ANN001
        task_id=None, task=None, args=None, kwargs=None, state=None, **_kw
    ):
        started = _TASK_STARTS.pop(task_id, None)
        try:
            from citadel_contracts.telemetry import record_task

            record_task(
                getattr(task, "name", "unknown"),
                "success" if state == "SUCCESS" else "failure",
                (_time.perf_counter() - started) * 1000 if started else 0.0,
                task_id=task_id or "",
                queue_name=_task_queue(task),
                case_id=_case_id_of(task, kwargs, args),
                retries=getattr(getattr(task, "request", None), "retries", None),
                **{"labels": {"celery_state": state or "UNKNOWN"}},
            )
        except Exception:  # noqa: BLE001 — telemetry must never fail a task
            pass

    @_signals.task_failure.connect(weak=False)
    def _telemetry_task_failure(  # noqa: ANN001
        task_id=None, exception=None, args=None, kwargs=None, einfo=None, sender=None, **_kw
    ):
        try:
            from citadel_contracts.telemetry import record_error

            record_error(
                exception,
                event="task_failure",
                stack=str(einfo) if einfo else "",
                correlation_id=task_id or "",
                case_id=_case_id_of(sender, kwargs, args),
                **{"task.name": getattr(sender, "name", "unknown"), "task.id": task_id or ""},
            )
        except Exception:  # noqa: BLE001
            pass

except Exception:  # noqa: BLE001 — celery signals unavailable (import-time edge)
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
    # These bound the WHOLE task and must stay above the per-parser wall-clock
    # budget (resource_limits.DEFAULT_WALL_TIMEOUT_SEC, default 2 h) — otherwise
    # Celery kills a parser the resource limiter was still happy to run, and the
    # analyst gets a bare "SoftTimeLimitExceeded()" instead of a result. That is
    # exactly what happened with Hayabusa over a large EVTX corpus: the soft limit
    # was 1 h while the parser budget was 2 h, so any run past an hour could only
    # ever fail. Defaults now leave headroom over the parser budget for the
    # download/index phases either side of it, and both are env-tunable.
    task_soft_time_limit=int(os.getenv("CELERY_SOFT_TIME_LIMIT", "10800")),  # 3 h
    task_time_limit=int(os.getenv("CELERY_TIME_LIMIT", "12600")),  # SIGKILL at 3.5 h
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
        # Must not be below the hard time limit, or the broker redelivers a task
        # that is still legitimately running and it gets executed twice.
        "visibility_timeout": int(os.getenv("CELERY_TIME_LIMIT", "12600")),
        "socket_keepalive": True,
        "retry_policy": {
            "timeout": 5.0,
        },
    },
    broker_connection_retry_on_startup=True,
)


def _check_time_limits() -> list[str]:
    """Return a warning per time-limit inversion in the current configuration.

    The task limits, the per-parser wall-clock budget, and the broker visibility
    timeout are three independent knobs that must stay ordered:

        parser wall budget  <  soft task limit  <  hard task limit  <=  visibility

    When they invert, the symptom is a module run that could never have
    succeeded — a bare ``SoftTimeLimitExceeded()`` with no output — rather than
    an obvious misconfiguration. Checked at import so it shows up in the worker's
    startup log instead of being discovered by a failed 2-hour Hayabusa run.
    """
    warnings: list[str] = []
    soft = int(app.conf.task_soft_time_limit or 0)
    hard = int(app.conf.task_time_limit or 0)
    vis = int((app.conf.broker_transport_options or {}).get("visibility_timeout") or 0)
    parser = int(os.getenv("PARSER_WALL_TIMEOUT_SEC", "7200"))

    if soft and parser >= soft:
        warnings.append(
            f"PARSER_WALL_TIMEOUT_SEC ({parser}s) >= task_soft_time_limit ({soft}s): "
            "a parser allowed to run that long will always be killed by Celery first. "
            "Raise CELERY_SOFT_TIME_LIMIT or lower PARSER_WALL_TIMEOUT_SEC."
        )
    if soft and hard and soft >= hard:
        warnings.append(
            f"task_soft_time_limit ({soft}s) >= task_time_limit ({hard}s): "
            "tasks are SIGKILLed with no chance to record why they stopped."
        )
    if hard and vis and vis < hard:
        warnings.append(
            f"broker visibility_timeout ({vis}s) < task_time_limit ({hard}s): "
            "the broker will redeliver still-running tasks, executing them twice."
        )
    return warnings


for _w in _check_time_limits():
    logger.warning("Celery time-limit misconfiguration: %s", _w)


if __name__ == "__main__":
    app.start()
