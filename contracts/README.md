# Citadel — Shared Contracts

The tools in the Citadel suite stay independent because they speak only these contracts — never each other's internals. Anything that crosses a tool boundary is defined here and versioned independently of any single tool.

| Contract | File | Purpose |
|----------|------|---------|
| ForensicEvent | `forensic_event.schema.json` | The canonical event a Babel parser yields, before Rosetta enriches it to full ECS. |
| ECS extension | `ecs_extension.md` | The ECS v8 + OSSEM fields Rosetta adds on top of a ForensicEvent. |
| Artifact bundle | `bundle_manifest.schema.json` | The portable unit Talon hands to Sluice (`manifest.json` inside `bundle/`). |
| brick.yaml | `brick.schema.json` | The per-tool manifest declaring inputs, outputs, schema versions, deps, health. |
| Collector agent | `collector.proto` | gRPC service between the Talon remote agent and Sluice/Citadel. |
| Bus topics | `bus_topics.md` | The Redis-Streams/NATS/Kafka topic contract for the async pipeline. |

## Versioning

Each contract carries a `$id` with a version segment. A tool's `brick.yaml` pins the contract versions it produces/consumes under `produces.schema`. Breaking a contract is a major bump and a coordinated change across the suite.

## Pipeline

```
Talon → Sluice → Babel → Rosetta → {store, Sigil, Anvil, Augur} → Citadel timeline → Pilot → Scribe → console
```
