# Sluice Worker — Intake & Routing Runtime

> The Celery worker that does Sluice's job: detect, dedup, route, parse, validate, emit.

**Status: built** — the async execution half of [Sluice](https://github.com/sltcnb/sluice).

Sluice-worker is the background worker that turns received evidence into indexed events. It downloads each artifact from MinIO, detects its type, loads the matching **Babel** plugin, runs `parse()`, validates each `ForensicEvent` against the contract, indexes the result into Elasticsearch, and (optionally) publishes it onto the Redis Streams bus. It also drives Anvil module runs and image harvesting.

## Pipeline position

```
Talon (uploads) ──▶ Sluice (intake) ──▶ sluice-worker (Celery) ──ForensicEvent──▶ Elasticsearch + bus ──▶ Rosetta …
```

## Contract

sluice-worker has **no `brick.yaml` of its own** — the declared surface lives in the [Sluice repo](https://github.com/sltcnb/sluice)'s `brick.yaml`: consumes `bundle_manifest/v1` (any content type; sniffs magic → extension → filename), produces `forensic_event/v1`, health at `/healthz`. At runtime the worker enforces that surface: every event bound for the bus is checked with `citadel_contracts.validate_forensic_event`, and emission follows the contracts `bus_topics` spec — batches on the `events.parsed` Redis Stream (`bus:events.parsed:{company}`), at-least-once, consumers dedup by sha256.

## Inputs → Outputs

- **Inputs** — Celery tasks (`ingest.*`, `module.*`, `harvest.*`) carrying a file path, `case_id`, `company`, and optional `force_artifact_type`. Files are pulled from the MinIO bucket (`MINIO_BUCKET`, default `forensics-cases`).
- **Outputs** — `ForensicEvent` objects bulk-indexed to Elasticsearch; published to the Redis Stream `bus:events.parsed:{company}` when `BUS_EMIT_ENABLED=true`. Dedup state lives in Redis at `fo:ingest:seen_sha256:{case_id}` (7-day TTL).

## Install

Runtime deps are tracked in `requirements.txt` (Python 3.11+); the shared contract package comes from [citadel-contracts](https://github.com/sltcnb/citadel-contracts) — in the platform monorepo image it is installed from `tools/citadel_contracts/`.

```bash
pip install -r requirements.txt
pip install git+https://github.com/sltcnb/citadel-contracts
```

Or build the container image. The Dockerfile bakes in the forensic toolchain (Hayabusa, RegRipper, plaso, ExifTool, de4dot, pytsk3) plus `citadel_contracts` and the built-in Babel parsers / Anvil modules, so it must be built from the platform monorepo root:

```bash
docker build -f tools/sluice-worker/Dockerfile -t sluice-worker .
```

## Configuration

All settings are environment variables (defaults verified in code):

| Variable | Default | Purpose |
|----------|---------|---------|
| **Broker / storage** | | |
| `REDIS_URL` | `redis://redis-service:6379/0` | Celery broker + backend, dedup, run state, logs |
| `MINIO_ENDPOINT` | `minio-service:9000` | Artifact blob store |
| `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` | `minioadmin` | MinIO credentials |
| `MINIO_BUCKET` | `forensics-cases` | Bucket artifacts are pulled from |
| `ELASTICSEARCH_URL` | `http://elasticsearch-service:9200` | Event index |
| `BULK_SIZE` | `500` | Events per ES bulk request |
| **Worker** | | |
| `CELERY_CONCURRENCY` | `4` | Worker processes per replica (Docker CMD) |
| `WORKER_MAX_TASKS` | `50` | Recycle a worker process after N tasks |
| `INGESTER_DIR` | `/app/sluice` | Custom (Studio-created) ingesters volume |
| `MODULES_DIR` | `/app/anvil` | Custom Anvil modules volume |
| `INTERNAL_API_URL` | `http://api-service:8000` | Citadel API for the post-ingest finalize chain |
| `INTERNAL_SERVICE_TOKEN` | *(empty — chain skipped)* | Auth token for that internal call |
| `CITADEL_LOG_TO_REDIS` | `true` | Ship JSON logs to `citadel:logs:processor` |
| `CUCKOO_API_URL` / `CUCKOO_API_TOKEN` | *(empty — optional)* | Cuckoo sandbox integration |
| **Module sandbox** (custom module subprocess limits) | | |
| `SANDBOX_CPU_SECONDS` | `3600` | CPU-time rlimit |
| `SANDBOX_MEMORY_BYTES` | `2147483648` (2 GiB) | Address-space rlimit |
| `SANDBOX_FSIZE_BYTES` | `524288000` (500 MiB) | Max file a module may write |
| `SANDBOX_NPROC` | `64` | Max processes/threads |
| `SANDBOX_TIMEOUT_SEC` | `1800` | Wall-clock kill timeout |
| **Bus emit** | | |
| `BUS_EMIT_ENABLED` | off (`1/true/yes/on` to enable) | Publish parsed events to `events.parsed` |
| `BUS_EMIT_BATCH_SIZE` | `500` | Events per stream entry (XADD) |
| `BUS_EMIT_MAX_EVENTS` | `50000` | Cap on events collected for the bus per ingest |
| `INGEST_DEDUP_TTL` | `604800` (7 days) | TTL of the per-case sha256 dedup set |

## How it runs

```bash
celery -A celery_app worker --loglevel=info --concurrency=${CELERY_CONCURRENCY:-4} -Q ingest,modules,default
# or containerized (same CMD baked into the image):
docker run -e REDIS_URL=redis://redis:6379/0 -e BUS_EMIT_ENABLED=true sluice-worker
```

- **Queues** — `ingest` (I/O-bound parsing), `modules` (CPU-bound Anvil analysis + harvest), `default` (fallback).
- **Resilience** — `worker_prefetch_multiplier=1`; process recycling after `WORKER_MAX_TASKS` to bound memory on large EVTX/MFT/registry hives; soft/hard time limits (1 h / 2 h); `task_acks_late` + `task_reject_on_worker_lost` re-queue on crash.
- **Observability** — JSON logs, Prometheus `/metrics`, `/healthz` + `/readyz` (`observability.py`); per-service logs shipped to `citadel:logs:processor`.

## Key modules

- `celery_app.py` — Celery config, queues, task routing.
- `plugin_loader.py` — discovers and routes to Babel plugins (`PluginLoader`); no registry required, custom parsers picked up on scan.
- `bus_emit.py` — writes to `bus:events.parsed:{company}`, idempotent via the SHA-256 dedup set.
- `tasks/ingest_task.py` — core ingest (download → detect → parse → index).
- `tasks/module_task.py` + `_module_sandbox.py` — sandboxed Anvil module runner.
- `tasks/harvest_task.py` — server-side image traversal (pytsk3) for in-app Harvest.
- `routing_coverage.py` — verifies every Babel parser has a routable handler.

## Tests

```bash
pytest tests/
```

---

Part of the **[Citadel](https://github.com/sltcnb/citadel)** DFIR suite. Deployed as the **processor** service: the execution half of [Sluice](https://github.com/sltcnb/sluice) — this `worker/` dir lives in the sluice repo alongside the declared surface, downstream of [Talon](https://github.com/sltcnb/talon) acquisitions and uploads, feeding Elasticsearch and — via the `events.parsed` bus — [Rosetta](https://github.com/sltcnb/rosetta) and the Citadel timeline.
