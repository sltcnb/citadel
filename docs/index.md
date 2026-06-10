# Citadel

> A digital-forensics and incident-response (DFIR) platform built from independent, standalone tools — each useful on its own, all composed by **Citadel**.

*(Renamed from traceX. The full suite plan lives in the root [`ROADMAP.md`](roadmap.md).)*

## What Citadel is

Citadel is a DFIR platform built as a **suite of standalone tools**. Each tool has its own name, repository, CLI, and reason to exist — an analyst can pick up any one of them alone, with no platform required. Citadel is the integrator: it wires the tools together over shared contracts into an end-to-end pipeline, from acquisition to a finished report.

Lifecycle coverage:

- **Acquire** — Talon collects artifacts from hosts, disks, and cloud.
- **Ingest & parse** — Sluice routes every artifact to Babel (multi-format parser library); Rosetta canonicalizes to ECS v8 + OSSEM.
- **Detect & analyze** — Sigil matches Sigma/YARA; Anvil runs heavy analyzers in a sandbox; Augur enriches indicators; Pilot reasons over a case autonomously.
- **Specialize** — Wraith (memory), Wiretap (network), Nimbus (cloud), Warden (identity).
- **Report** — Scribe renders HTML/PDF/STIX/MISP.
- **Integrate** — Citadel provides cases, timeline, search, multi-tenancy, and the console.

## Guiding principles

- **Standalone-first** — every tool runs as a CLI without the platform. The platform is an integrator, not a prerequisite.
- **Contract-first** — every tool ships a `brick.yaml` manifest declaring inputs, outputs, and schema versions. Tools speak only [contracts](contracts.md), never each other's internals.
- **Single responsibility** — one tool, one job.
- **Schema is the lingua franca** — `ForensicEvent → ECS v8 + OSSEM`, plus artifact bundles. Never bespoke formats.
- **Stateless compute, stateful substrate** — state lives in Elasticsearch, MinIO, Redis.
- **Replaceable** — swap a rule pack, parser, or index without touching neighbours.

## The pipeline, in one line

```
Talon → Sluice → Babel → Rosetta → {store, Sigil, Anvil, Augur} → Citadel timeline → Pilot → Scribe → console
```

See [Architecture](architecture.md) for the diagram, bus topics, and shared layers, and the [Tool Suite](tools.md) for the full list of 14 tools.
