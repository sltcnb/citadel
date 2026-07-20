"""
Direct Celery task dispatch for the ForensicsOperator API.

Bypasses Celery's routing machinery (exchange + binding-table lookups) and
pushes Celery v5-compatible JSON messages straight to the Redis list that
processor workers consume via BLPOP.  This avoids the class of silent message
drops caused by exchange/routing-key mismatches between the minimal API Celery
app and the processor's 'forensics' direct exchange.
"""

from __future__ import annotations

import base64
import json
import logging
import uuid

import redis as _redis

from config import settings

logger = logging.getLogger(__name__)


# ── Priority ───────────────────────────────────────────────────────────────
# Every base queue ("ingest", "modules") has a "_high" twin. The processor's
# Celery worker is started with -Q listing every *_high queue before its base
# queue (see tools/sluice/worker/Dockerfile), and Kombu's Redis transport
# issues a single BLPOP/BRPOP across all subscribed queue keys in the order
# given — Redis returns from the first non-empty key. So a high-priority queue
# always drains ahead of its base queue whenever both have pending work, with
# no custom scheduler needed.
PRIORITY_HIGH = "high"
PRIORITY_DEFAULT = "default"

# Celery message "priority" field (AMQP-style: lower = higher priority). Not
# used by the redis-transport queue selection above, but kept accurate for
# any tooling/metrics that inspects the envelope.
_PRIORITY_FIELD = {PRIORITY_HIGH: 0, PRIORITY_DEFAULT: 5}


def _queue_for(base_queue: str, priority: str) -> str:
    if priority == PRIORITY_HIGH:
        return f"{base_queue}_high"
    return base_queue


def _push(
    queue: str,
    task_name: str,
    task_id: str,
    args: list,
    kwargs: dict | None = None,
    priority: str = PRIORITY_DEFAULT,
) -> None:
    """
    Build a Celery v5 JSON message envelope and RPUSH it to *queue* (or its
    "_high" twin when *priority* is ``"high"`` — see PRIORITY_HIGH above).

    The processor workers consume from these Redis lists via Kombu's BLPOP
    loop.  Any well-formed Celery message pushed here will be received and
    executed by the worker regardless of exchange/binding configuration.
    """
    queue = _queue_for(queue, priority)
    kw = kwargs or {}
    body_b64 = base64.b64encode(
        json.dumps(
            [args, kw, {"callbacks": None, "errbacks": None, "chain": None, "chord": None}]
        ).encode()
    ).decode()

    delivery_id = uuid.uuid4().hex

    envelope = json.dumps(
        {
            "body": body_b64,
            "content-encoding": "utf-8",
            "content-type": "application/json",
            "headers": {
                "lang": "py",
                "task": task_name,
                "id": task_id,
                "shadow": None,
                "eta": None,
                "expires": None,
                "group": None,
                "group_index": None,
                "retries": 0,
                "timelimit": [None, None],
                "root_id": task_id,
                "parent_id": None,
                "origin": "api",
                "utc": True,
                "argsrepr": repr(args),
                "kwargsrepr": repr(kw),
            },
            "properties": {
                "correlation_id": task_id,
                "reply_to": delivery_id,
                "delivery_mode": 2,
                "delivery_info": {
                    "exchange": "",
                    "routing_key": queue,
                },
                "priority": _PRIORITY_FIELD.get(priority, 5),
                "body_encoding": "base64",
                "delivery_tag": delivery_id,
            },
        }
    )

    r = _redis.Redis.from_url(settings.REDIS_URL)
    list_len = r.rpush(queue, envelope)
    logger.info(
        "Dispatched %s[%s] → queue '%s' (depth now %d)", task_name, task_id, queue, list_len
    )


def dispatch_ingest(
    job_id: str, case_id: str, minio_key: str, filename: str, priority: str = PRIORITY_DEFAULT
) -> None:
    _push(
        "ingest",
        "ingest.process_artifact",
        job_id,
        [job_id, case_id, minio_key, filename],
        priority=priority,
    )


def dispatch_s3_transfer(
    job_id: str,
    case_id: str,
    s3_config_key: str,
    s3_key: str,
    filename: str,
    priority: str = PRIORITY_DEFAULT,
) -> None:
    """Dispatch the S3→MinIO streaming task that runs fully in the background.

    Defaults to normal priority (same tier as a direct upload): a bulk S3
    import competes with, but never blocks, interactive module/harvest runs
    dispatched at PRIORITY_HIGH.
    """
    _push(
        "ingest",
        "ingest.s3_transfer",
        job_id,
        [job_id, case_id, s3_config_key, s3_key, filename],
        priority=priority,
    )


def dispatch_module(
    run_id: str,
    case_id: str,
    module_id: str,
    source_files: list,
    params: dict,
    priority: str = PRIORITY_HIGH,
) -> None:
    """Dispatch an analyst-triggered module run.

    Defaults to PRIORITY_HIGH — an analyst is watching this run in the UI, so
    it should drain ahead of any queued bulk background ingest.
    """
    _push(
        "modules",
        "module.run",
        run_id,
        [run_id, case_id, module_id, source_files, params],
        priority=priority,
    )


def dispatch_harvest(
    run_id: str,
    case_id: str,
    level: str,
    categories: list,
    minio_object_key: str | None,
    mounted_path: str | None,
    priority: str = PRIORITY_HIGH,
) -> None:
    """Dispatch a forensic harvest/triage run to the modules queue.

    Defaults to PRIORITY_HIGH for the same reason as dispatch_module: an
    analyst kicked this off interactively and is waiting on the result.
    """
    _push(
        "modules",
        "harvest.run_harvest",
        run_id,
        [],
        kwargs={
            "run_id": run_id,
            "case_id": case_id,
            "level": level,
            "categories": categories,
            "minio_object_key": minio_object_key,
            "mounted_path": mounted_path,
        },
        priority=priority,
    )
