# Bus Topics

Asynchronous pipeline stages communicate over a message bus — **Redis Streams** by default, **NATS/Kafka** pluggable. Each stage is a consumer group; backpressure and replay come from stream semantics.

```
artifacts.received
        │  (Sluice picks up a bundle/file)
        ▼
events.parsed            ← Babel emits ForensicEvents
        │
        ▼
events.normalized        ← Rosetta emits ECS v8 + OSSEM
        │
        ├──► events.indexed        (Citadel store → Elasticsearch)
        ├──► detections.matched    (Sigil)
        ├──► modules.completed      (Anvil)
        └──► intel.enriched         (Augur)
```

## Contract

| Topic | Producer | Consumers | Payload |
|-------|----------|-----------|---------|
| `artifacts.received` | Talon / upload API | Sluice | bundle ref + `bundle_manifest` |
| `events.parsed` | Babel (via Sluice) | Rosetta | `forensic_event/v1` batch |
| `events.normalized` | Rosetta | store, Sigil, Anvil, Augur | ECS v8 event batch |
| `events.indexed` | Citadel store | timeline | doc ids |
| `detections.matched` | Sigil | Citadel, webhooks | detection + rule id |
| `modules.completed` | Anvil | Citadel | findings + run id |
| `intel.enriched` | Augur | Citadel | enriched IOCs (STIX) |

## Guarantees
- **At-least-once** delivery; consumers must be **idempotent** (dedup by event sha256 / doc id).
- Replay supported by reading from an earlier stream id.
- Per-tenant isolation: topic keys carry the company id.
