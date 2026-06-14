# Citadel Tool Suite

Citadel is built from **standalone tools**. Each has its own name, directory,
CLI, and `brick.yaml` manifest, and each is useful on its own. They compose only
through the shared contracts in [`../contracts/`](../contracts/) — never by
importing each other. The platform (`../api` + `../frontend`) pins and composes
them.

Machine-readable index: [`SUITE.yaml`](SUITE.yaml).

## Pipeline

```
Talon ──bundle──▶ Sluice ──route──▶ Babel ──ForensicEvent──▶ Rosetta ──ECS──▶ ┐
                                                                               ├─▶ store (timeline/search)
                                                              Sigil ◀──────────┤   detections
                                                              Anvil ◀──────────┤   findings
                                                              Augur ◀──────────┘   enriched intel
                              Pilot (agent) drives the tools ·  Scribe renders the report
```

## In-platform tools (`tools/` + `api/`)

| Tool | Role | Input → Output | Dir | CLI | Status |
|------|------|----------------|-----|-----|--------|
| **Talon** | Acquisition agent | host/disk/cloud → artifact **bundle** (manifest + sha256 blobs) | `tools/talon` | `talon collect --out case.bundle` | built |
| **Sluice** | Intake & routing | bundle/file/dir → routed files → **ForensicEvent** stream (+ Redis bus) | `tools/sluice` + `tools/sluice-worker` | `sluice ingest case.bundle` | built |
| **Babel** | Parser library (43+) | artifact → **ForensicEvent** | `tools/babel` | `babel parse Security.evtx` | built |
| **Rosetta** | Canonicalizer | ForensicEvent → **ECS v8 + OSSEM** (CLI + watch daemon) | `tools/rosetta` | `rosetta normalize ev.jsonl` | built |
| **Sigil** | Detection engine | ECS events + rules → **detections** (Sigma→ES convert, ATT&CK coverage) | `tools/sigil` | `sigil validate ./rules/` | partial |
| **Anvil** | Analysis runner | artifact + module → **findings** (typed `Result`, DAG pipeline) | `tools/anvil` | `anvil run volatility3 -a mem.raw` | built |
| **Augur** | Intel enrichment | IOCs → **scored STIX / MISP** (5 sources, TTL cache) | `tools/augur` | `augur enrich iocs.json` | partial |
| **Pilot** | Investigation agent | case/index → **autonomous report** (LLM agent loop) | `api` LLM layer | `pilot investigate --case ID` | built |
| **Scribe** | Report engine | case → **HTML/PDF/STIX/MISP** | `api/routers/reports.py` | `scribe report --case ID -f pdf` | partial |
| **Citadel** | Platform / integrator | composes the suite; cases, timeline, search, console | `api` + `frontend` | `docker compose --profile full up` | built |

## Contracts every tool speaks

- **ForensicEvent** ([`forensic_event.schema.json`](../contracts/forensic_event.schema.json)) — required `timestamp` (ISO-8601 **Z**) + `message`; `raw` retained for structured types.
- **ECS extension** ([`ecs_extension.md`](../contracts/ecs_extension.md)) — Rosetta's ECS v8 + OSSEM/ATT&CK output.
- **Artifact bundle** ([`bundle_manifest.schema.json`](../contracts/bundle_manifest.schema.json)) — Talon → Sluice unit.
- **brick.yaml** ([`brick.schema.json`](../contracts/brick.schema.json)) — per-tool manifest (consumes/produces/deps/health).
- **Bus topics** ([`bus_topics.md`](../contracts/bus_topics.md)) — `events.parsed → events.normalized → {indexed, detections, modules, intel}`.
- **Parser contract** ([`citadel_contracts`](citadel_contracts/)) — `BasePlugin`; subclass it to add a parser pack (drop-in, no platform changes).

## Transport (per edge)
Redis Streams for the pipeline data-plane · gRPC + S3/MinIO for Talon (remote, mTLS) · in-process via `citadel_contracts` for the Sluice→Babel hot path.

## Testing
`../scripts/run_tests.sh` runs every tool's suite + the Babel→Rosetta→Sigil integration test.
