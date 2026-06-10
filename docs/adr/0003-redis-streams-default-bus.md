# 3. Redis Streams as the default pipeline bus

- Status: Accepted
- Date: 2026-06-08

## Context

The pipeline stages (parse → normalize → index/detect/analyze/enrich) run asynchronously and at different rates; hot stages (Babel/Anvil) must scale on backlog. We need durable hand-off, backpressure, replay, and consumer groups — without forcing a heavy broker on small standalone deployments.

## Decision

Use **Redis Streams** as the default message bus, with **NATS/Kafka pluggable** for larger deployments. Redis is already a dependency (queues, cancel flags, caches), so it adds no new substrate for the common case.

Topics: `artifacts.received → events.parsed → events.normalized → {events.indexed, detections.matched, modules.completed, intel.enriched}` (see `contracts/bus_topics.md`). Each stage is a consumer group.

Delivery is **at-least-once**; all consumers must be **idempotent** (dedup by event sha256 / doc id). Replay is reading from an earlier stream id. Topic keys carry the company id for per-tenant isolation.

## Consequences

- **+** No extra broker for small/standalone deployments; reuses existing Redis.
- **+** Consumer groups give backpressure + horizontal scaling of hot workers.
- **+** Replay and at-least-once durability via stream semantics.
- **−** Consumers must be written idempotently — duplicate delivery is expected, not exceptional.
- **−** Redis Streams has weaker retention/throughput than Kafka at very large scale; hence the pluggable abstraction.
