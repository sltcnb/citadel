# 1. Standalone-first tool suite composed by Citadel

- Status: Accepted
- Date: 2026-06-08

## Context

Citadel covers the full DFIR lifecycle — acquisition, ingest, parsing, normalization, detection, analysis, enrichment, investigation, reporting, and the domain specializations (memory, network, cloud, identity). A single monolith would couple these concerns, make any one capability hard to adopt in isolation, and slow independent release.

## Decision

Build the platform as a **suite of standalone tools** (Talon, Sluice, Babel, Rosetta, Sigil, Anvil, Augur, Pilot, Scribe, Wraith, Wiretap, Nimbus, Warden). Each tool:

- has its own name, repository, CLI, and reason to exist;
- runs standalone without the platform;
- ships a `brick.yaml` manifest declaring its inputs, outputs, and schema versions;
- communicates only through shared **contracts** (`contracts/`), never another tool's internals.

**Citadel** is the integrator: it pins each tool at a tested version and composes them over the contracts into an end-to-end pipeline. Physically, the standalone tool components live under `tools/`; the platform (API + console) is the repo root.

## Consequences

- **+** Each tool is independently useful, testable, and shippable; analysts can adopt one tool or the whole platform.
- **+** Single-responsibility boundaries; a parser pack or rule pack is replaceable without touching neighbours.
- **+** Clear contribution surface and clean CI per tool.
- **−** Requires disciplined contract versioning and a composition layer (the bus + gRPC wiring).
- **−** Some capabilities (Sigil, Pilot, Scribe, Augur) currently live inside the platform and must be extracted into their own tool repos over Phases 2–3.
