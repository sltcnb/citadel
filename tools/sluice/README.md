# Sluice — Intake & Routing

> Receive any evidence, recognise it, dedup it, and route each artifact to the right parser.

**Status: built** — intake entry point + async routing worker.

Sluice is the front door of the pipeline. It receives evidence (single files, triage ZIPs, disk images, or a Talon `.citadel` bundle), sniffs each artifact's type (**magic → extension → filename**), deduplicates by SHA-256, picks the matching **Babel** parser, validates every emitted `ForensicEvent` against the contract, and publishes the parsed stream onto the bus.

This repo holds Sluice's `brick.yaml` + `capabilities.yaml` (its declared surface) and, under [`worker/`](worker/), the runtime that executes intake and routing — the Celery execution worker.

## Pipeline position

```
Talon ──bundle──▶ Sluice ──ForensicEvent──▶ Rosetta ──ECS──▶ store / Sigil / Anvil / Augur
                    │
                    └─ routes each artifact to a Babel parser
```

## Inputs → Outputs

- **Consumes** — anything (`content_types: *`, `filenames: *`); accepts a Talon artifact bundle (`contracts/bundle_manifest/v1.json`) or loose files/dirs.
- **Produces** — a validated `ForensicEvent` stream (`contracts/forensic_event/v1.json`), emitted to the bus (`events.parsed`) and indexed. Artifact types are whatever the selected Babel parser yields.
- **Dependencies** — Babel (parsers), Redis (bus + queue), MinIO (blob store).
- **Health** — `GET /healthz`.

## Declared capability

`ingest_upload` — "Upload one or more artifacts; Sluice routes each to its parser."

- `files` (path, required) — artifacts, triage ZIPs, disk images, or a `.citadel` bundle.
- `artifact_type` (string, optional) — force a type, overriding auto-detection for ambiguous files.

Output: `events → timeline`.

## Contracts

Sourced from `brick.yaml`; all schemas are versioned in the [citadel-contracts](https://github.com/sltcnb/citadel-contracts) repo (Python package `citadel_contracts`, `pip install git+https://github.com/sltcnb/citadel-contracts`).

- **Consumes** — `contracts/bundle_manifest/v1.json` (Talon bundle), plus arbitrary content types/filenames (`*`) for loose uploads.
- **Produces** — `contracts/forensic_event/v1.json`; artifact types are whatever the selected Babel parser yields.

## Install & configuration

The declared surface (`brick.yaml`, `capabilities.yaml`, this README) needs no install. The runtime lives in [`worker/`](worker/) — see its README for env vars, queues and the celery command.

## In Citadel

Sluice is the intake stage behind the dashboard upload and the Harvest flow. It runs Babel in-process for the hot parse path, validates with `citadel_contracts.validate_forensic_event`, and feeds Rosetta + the timeline. See [`worker/`](worker/) for queues, dedup keys, and bus emission, and `bus_topics.md` in [citadel-contracts](https://github.com/sltcnb/citadel-contracts).

## Part of the Citadel suite

Sluice is the intake stage of [Citadel](https://github.com/sltcnb/citadel). Upstream: [Talon](https://github.com/sltcnb/talon) (artifact bundles). Downstream: [Babel](https://github.com/sltcnb/babel) parsers, then [Rosetta](https://github.com/sltcnb/rosetta). Runtime dependencies (`brick.yaml`): Babel, Redis (bus + queue), MinIO (blob store). Runtime worker: in-repo under [`worker/`](worker/). Contracts: [citadel-contracts](https://github.com/sltcnb/citadel-contracts).
