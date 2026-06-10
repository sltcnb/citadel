# 4. Transport chosen per edge, not uniformly

- Status: Accepted
- Date: 2026-06-10

## Context

Tools must compose without coupling, but a single transport for every edge is wrong: the pipeline data-plane is high-volume and async, the agent/control calls are synchronous, and acquisition is cross-host. Forcing gRPC everywhere adds latency + ops on the hot path; forcing the bus everywhere makes synchronous "call a tool, wait for the answer" awkward.

## Decision

Pick the transport by the **task shape** of each edge:

- **Message bus (Redis Streams) — the default data-plane.** `events.parsed → events.normalized → {events.indexed, detections.matched, modules.completed, intel.enriched}`. Async, replayable, backpressured, autoscaled. Use the bus wherever it is the cleanest fit.
- **gRPC — reserved for acquisition + remote/agent edges.** **Talon → Sluice** stays gRPC (chunked, resumable, **mTLS**) with blob payloads in **S3/MinIO**. Pilot↔tools / API↔tools may use gRPC only where a synchronous typed call is genuinely needed.
- **In-process via the contract — the Sluice → Babel hot path.** Parsing is the highest-frequency edge (tens of thousands of events per file). Sluice loads Babel parser packs **in-process** through the shared `citadel_contracts` package (`BasePlugin`), with **no import of Babel internals**. This is the fastest option and stays interchangeable: any directory of modules subclassing `citadel_contracts.BasePlugin` is a drop-in parser pack. A remote-Babel gRPC mode can be added behind a flag later, only if parsing needs independent autoscaling.

## Consequences

- **+** Hot path pays no serialization/network cost; pipeline gets bus durability/scaling; acquisition gets auth + resumability.
- **+** Interchangeability without microservice sprawl — every edge is a versioned contract (`.proto`, JSON Schema, or the `citadel_contracts` ABC), but only the edges that benefit run over a network.
- **+** Sluice no longer imports Babel; either tool can be swapped/replaced independently.
- **−** Two-plus transports to operate and reason about (bus + gRPC + in-process).
- **−** The "remote Babel" path is deferred, so independent parser autoscaling isn't available until that mode is built.
