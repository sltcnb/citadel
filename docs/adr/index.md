# Architecture Decision Records

ADRs capture the significant, hard-to-reverse decisions behind Citadel. Format: [MADR](https://adr.github.io/madr/).

| # | Decision | Status |
|---|----------|--------|
| [0001](0001-standalone-first-tool-suite.md) | Standalone-first tool suite composed by Citadel | Accepted |
| [0002](0002-forensic-event-ecs-canonical-schema.md) | ForensicEvent → ECS v8 + OSSEM as the canonical schema | Accepted |
| [0003](0003-redis-streams-default-bus.md) | Redis Streams as the default pipeline bus | Accepted |
| [0004](0004-transport-per-edge.md) | Transport chosen per edge (bus default · gRPC for Talon/agent · in-process contract for Sluice→Babel) | Accepted |
