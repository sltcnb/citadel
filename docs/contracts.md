# Contracts

The tools in the Citadel suite stay independent because they speak only these contracts — never each other's internals. Anything that crosses a tool boundary is defined in `contracts/` and versioned independently of any single tool.

| Contract | File | Purpose |
|----------|------|---------|
| ForensicEvent | `contracts/forensic_event.schema.json` | The canonical event a Babel parser yields, before Rosetta enriches it to full ECS. |
| ECS extension | `contracts/ecs_extension.md` | The ECS v8 + OSSEM fields Rosetta adds on top of a ForensicEvent. |
| Artifact bundle | `contracts/bundle_manifest.schema.json` | The portable unit Talon hands to Sluice (`manifest.json` inside `bundle/`). |
| brick.yaml | `contracts/brick.schema.json` | The per-tool manifest declaring inputs, outputs, schema versions, deps, health. |
| Collector agent | `contracts/collector.proto` | gRPC service between the Talon remote agent and Sluice/Citadel. |
| Bus topics | `contracts/bus_topics.md` | The Redis-Streams/NATS/Kafka topic contract for the async pipeline. |

## Versioning

Each contract carries a `$id` with a version segment (e.g. `forensic_event/v1`). A tool's `brick.yaml` pins the contract versions it produces/consumes under `produces.schema`. Breaking a contract is a major bump and a coordinated change across the suite.

## ForensicEvent

The canonical event a Babel parser yields.

- **Required**: `timestamp` (ISO 8601 with `Z`, UTC) and `message` (human-readable summary).
- **Recommended**: `artifact_type` — the routing key from the ~90-entry artifact-type taxonomy (e.g. `windows_event`, `prefetch`, `syslog`, `docker_event`).
- Structured artifact types **must** carry their `raw` record to preserve fidelity for re-mapping.
- Optional: `timestamp_desc`, `os`, `source_path`, `parser`. Additional properties are allowed.

## ECS extension (Rosetta output)

Rosetta consumes a `ForensicEvent` and emits a document conforming to **ECS v8** plus **OSSEM** ATT&CK extensions — the schema the Citadel timeline, search, Sigil, and Scribe all read. Fields Rosetta adds include `@timestamp`, `ecs.version`, `event.category`/`event.type`/`event.action`, `host.*`, `user.*`, `process.*`, `source.*`/`destination.*`, `file.*`, `threat.technique.id`, `threat.tactic.name`, and `citadel.raw` (original record retained). Mapping is config-driven (per-`artifact_type` ECS maps, OSSEM relationships, Sigma-tag → ATT&CK table). Planned enrichment hooks: GeoIP, ASN, reverse-DNS on IPs.

## Artifact bundle

The portable unit Talon hands to Sluice. Layout:

```
bundle/  manifest.json | events.jsonl | blobs/<sha256> | bundle.sha256
```

`manifest.json` requires `session_id`, `hostname`, `os`, `started_at`, `artifacts[]`, and `artifact_count`. Each entry in `artifacts[]` carries `name`, `sha256` (64 hex chars), `size`, and `category`. Optional: `finished_at`, `total_bytes`, `errors[]`.

## brick.yaml

The per-tool manifest. Every tool ships one at its repo root, declaring how it composes into the suite; **standalone use never requires it.**

- **Required**: `name`, `kind`, `version`.
- `kind` is one of: `collector`, `intake`, `parser-lib`, `canonicalizer`, `detection`, `analysis-runner`, `enrichment`, `agent`, `report`, `domain-analyzer`, `platform`.
- `consumes`: `content_types`, `filenames`, `schema` (contract `$id`s consumed).
- `produces`: `schema` (contract `$id`s produced), `artifact_types`.
- `dependencies`: other suite tools or substrate (elasticsearch, redis, minio).
- `health`: HTTP `endpoint` for services, CLI `command` for tools.
- `status`: `built` | `partial` | `planned`.

## Bus topics

Asynchronous pipeline stages communicate over a message bus — **Redis Streams** by default, **NATS/Kafka** pluggable. Each stage is a consumer group; backpressure and replay come from stream semantics.

```
artifacts.received → events.parsed → events.normalized → {events.indexed, detections.matched, modules.completed, intel.enriched}
```

| Topic | Producer | Consumers |
|-------|----------|-----------|
| `artifacts.received` | Talon / upload API | Sluice |
| `events.parsed` | Babel (via Sluice) | Rosetta |
| `events.normalized` | Rosetta | store, Sigil, Anvil, Augur |
| `events.indexed` | Citadel store | timeline |
| `detections.matched` | Sigil | Citadel, webhooks |
| `modules.completed` | Anvil | Citadel |
| `intel.enriched` | Augur | Citadel |

**Guarantees**: at-least-once delivery; consumers must be idempotent (dedup by event sha256 / doc id). Replay by reading from an earlier stream id. Per-tenant isolation: topic keys carry the company id.
