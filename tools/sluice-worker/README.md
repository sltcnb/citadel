# Sluice Worker — Intake & Routing Runtime

> The Celery worker that does Sluice's job: detect, dedup, route, parse, validate, emit.

**Status: built** — the async execution half of [Sluice](../sluice).

Sluice-worker is the background worker that turns received evidence into indexed events. It downloads each artifact from MinIO, detects its type, loads the matching **Babel** plugin, runs `parse()`, validates each `ForensicEvent` against the contract, indexes the result into Elasticsearch, and (optionally) publishes it onto the Redis Streams bus. It also drives Anvil module runs and image harvesting.

## Pipeline position

```
Sluice (intake) ──▶ sluice-worker (Celery) ──ForensicEvent──▶ Elasticsearch + bus ──▶ Rosetta …
```

## Inputs → Outputs

- **Inputs** — Celery tasks (`ingest.*`, `module.*`, `harvest.*`) carrying a file path, `case_id`, `company`, and optional `force_artifact_type`. Files are pulled from the MinIO bucket (`MINIO_BUCKET`, default `forensics-cases`).
- **Outputs** — `ForensicEvent` objects bulk-indexed to Elasticsearch; published to the Redis Stream `bus:events.parsed:{company}` when `BUS_EMIT_ENABLED=true`. Dedup state lives in Redis at `fo:ingest:seen_sha256:{case_id}` (7-day TTL).

## How it runs

```bash
celery -A celery_app worker -Q ingest,modules,default
```

- **Queues** — `ingest` (I/O-bound parsing), `modules` (CPU-bound Anvil analysis + harvest), `default` (fallback).
- **Resilience** — `worker_prefetch_multiplier=1`; process recycling after `WORKER_MAX_TASKS` (default 50) to bound memory on large EVTX/MFT/registry hives; soft/hard time limits (1 h / 2 h); `task_acks_late` + `task_reject_on_worker_lost` re-queue on crash.
- **Observability** — JSON logs, Prometheus `/metrics`, `/healthz` + `/readyz` (`observability.py`); per-service logs shipped to `citadel:logs:processor`.

## Key modules

- `celery_app.py` — Celery config, queues, task routing.
- `plugin_loader.py` — discovers and routes to Babel plugins (`PluginLoader`); no registry required, custom parsers picked up on scan.
- `bus_emit.py` — writes to `bus:events.parsed:{company}`, idempotent via the SHA-256 dedup set.
- `tasks/ingest_task.py` — core ingest (download → detect → parse → index).
- `tasks/module_task.py` + `_module_sandbox.py` — sandboxed Anvil module runner.
- `tasks/harvest_task.py` — server-side image traversal (pytsk3) for in-app Harvest.
- `routing_coverage.py` — verifies every Babel parser has a routable handler.

## In Citadel

This worker is deployed as the **processor** service. It is the data-plane that connects Sluice's intake decisions to Babel, Anvil, Elasticsearch, and the bus.
