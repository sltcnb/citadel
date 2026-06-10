# 2. ForensicEvent → ECS v8 + OSSEM as the canonical schema

- Status: Accepted
- Date: 2026-06-08

## Context

Tools must exchange events without knowing each other's formats. Babel has 43 parsers across Windows/Linux/macOS/mobile/network/generic; the timeline, search, Sigil, and Scribe all need one consistent shape. Inventing a bespoke inter-tool format would re-solve a problem the industry already standardized.

## Decision

Adopt a two-layer canonical schema:

1. **ForensicEvent** (`contracts/forensic_event.schema.json`) — the minimal event a Babel parser yields: required `timestamp` + `message`, recommended `artifact_type`, and a `raw` record required for structured types.
2. **ECS v8 + OSSEM** (`contracts/ecs_extension.md`) — Rosetta maps a ForensicEvent to full Elastic Common Schema with OSSEM ATT&CK extensions (`event.category/type`, `host.*`, `user.*`, `process.*`, `threat.technique.*`, …).

A ~90-entry artifact-type taxonomy is the routing key. Mapping is config-driven and consolidated into Rosetta, not scattered across parsers.

## Consequences

- **+** One lingua franca; the timeline/search/detection all read the same fields.
- **+** ECS is widely supported (Elasticsearch, Sigma backends) — low friction, reusable tooling.
- **+** `raw` retention preserves fidelity for re-mapping when schemas evolve.
- **−** Rosetta becomes a critical mapping component that must be maintained and version-pinned (ECS version).
- **−** Parsers must declare artifact types accurately for correct routing/mapping.
