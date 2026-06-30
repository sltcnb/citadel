# Citadel Tool Suite

Citadel is built from **standalone tools**. Each has its own name, directory,
CLI, and `brick.yaml` manifest, and each is useful on its own. They compose only
through the shared [`citadel_contracts`](citadel_contracts/) package + the schemas
in [`../contracts/`](../contracts/) — never by importing each other. The platform
(`../api` + `../frontend`) pins and composes them.

Machine-readable index: [`SUITE.yaml`](SUITE.yaml) · pinned versions: [`versions.yaml`](versions.yaml).

## Pipeline

```
Talon ──bundle──▶ Sluice ──route──▶ Babel ──ForensicEvent──▶ Rosetta ──ECS──▶ ┐
                                                                               ├─▶ store (timeline/search)
                                                              Sigil ◀──────────┤   detections
                                                              Anvil ◀──────────┤   findings
                                                              Augur ◀──────────┘   enriched intel
                              Pilot (agent) drives the tools ·  Scribe renders the report
```

## The tools

| Tool | Role | Input → Output | README |
|------|------|----------------|--------|
| **Talon** | Acquisition agent | host / disk / mount → artifact **bundle** | [talon](talon/README.md) |
| **Sluice** | Intake & routing | bundle / file / dir → routed **ForensicEvent** stream | [sluice](sluice/README.md) |
| **Sluice Worker** | Intake runtime | Celery worker: detect · dedup · route · parse · index · emit | [sluice-worker](sluice-worker/README.md) |
| **Babel** | Parser library | raw artifact → **ForensicEvent** (40+ parser packs) | [babel](babel/README.md) |
| **Rosetta** | Canonicalizer | ForensicEvent → **ECS v8 + OSSEM** (+ GeoIP/ASN/rDNS) | [rosetta](rosetta/README.md) |
| **Sigil** | Detection engine | ECS + rules → **detections** (Sigma→ES, ATT&CK coverage) | [sigil](sigil/README.md) |
| **Anvil** | Analysis runner | artifact + module → **findings** (typed `Result`, DAG) | [anvil](anvil/README.md) |
| **Augur** | Intel enrichment | IOCs → **scored STIX / MISP** | [augur](augur/README.md) |
| **Pilot** | Investigation agent | case / index → **autonomous report** (LLM loop) | [pilot](pilot/README.md) |
| **Scribe** | Report engine | case → **HTML / PDF / Markdown / DOCX** | [scribe](scribe/README.md) |
| **citadel_contracts** | Shared contract package | the types/validators every tool imports | [citadel_contracts](citadel_contracts/README.md) |

The platform itself (**Citadel** — `../api` + `../frontend`) composes the suite: cases, timeline, search, multi-tenancy, and the console.

## Contracts every tool speaks

- **ForensicEvent** ([`forensic_event.schema.json`](../contracts/forensic_event.schema.json)) — required `timestamp` (ISO-8601 **Z**) + `message`; `raw` retained for structured types.
- **ECS extension** ([`ecs_extension.md`](../contracts/ecs_extension.md)) — Rosetta's ECS v8 + OSSEM/ATT&CK output.
- **Artifact bundle** ([`bundle_manifest.schema.json`](../contracts/bundle_manifest.schema.json)) — the Talon → Sluice unit.
- **brick.yaml** ([`brick.schema.json`](../contracts/brick.schema.json)) — per-tool manifest (consumes/produces/deps/health).
- **Bus topics** ([`bus_topics.md`](../contracts/bus_topics.md)) — `events.parsed → events.normalized → {indexed, detections, modules, intel}`.
- **Parser contract** ([`citadel_contracts`](citadel_contracts/)) — `BasePlugin`; subclass it to add a parser pack (drop-in, no platform changes).

## Transport (per edge)

Redis Streams for the pipeline data-plane · gRPC + S3/MinIO for Talon (remote, mTLS) · in-process via `citadel_contracts` for the Sluice→Babel hot path.

## Testing

`../scripts/run_tests.sh` runs every tool's suite + the Babel→Rosetta→Sigil integration test.
