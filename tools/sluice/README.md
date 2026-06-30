# Sluice — Intake & Routing

> Receive any evidence, recognise it, dedup it, and route each artifact to the right parser.

**Status: built** — intake entry point + async routing worker.

Sluice is the front door of the pipeline. It receives evidence (single files, triage ZIPs, disk images, or a Talon `.citadel` bundle), sniffs each artifact's type (**magic → extension → filename**), deduplicates by SHA-256, picks the matching **Babel** parser, validates every emitted `ForensicEvent` against the contract, and publishes the parsed stream onto the bus.

This directory holds Sluice's `brick.yaml` + `capabilities.yaml` (its declared surface). The runtime worker that executes intake and routing lives in [`../sluice-worker`](../sluice-worker).

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

## In Citadel

Sluice is the intake stage behind the dashboard upload and the Harvest flow. It runs Babel in-process for the hot parse path, validates with `citadel_contracts.validate_forensic_event`, and feeds Rosetta + the timeline. See [`../sluice-worker`](../sluice-worker) for queues, dedup keys, and bus emission, and `../../contracts/bus_topics.md`.
