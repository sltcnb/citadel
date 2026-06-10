# ECS Extension (Rosetta output)

Rosetta consumes a `ForensicEvent` (see `forensic_event.schema.json`) and emits a document conforming to **ECS v8** plus **OSSEM** ATT&CK extensions. This is the schema the Citadel timeline, search, Sigil, and Scribe all read.

## Fields Rosetta adds

| Field | Source | Notes |
|-------|--------|-------|
| `@timestamp` | `timestamp` | ISO 8601 Z, copied/normalized |
| `ecs.version` | constant | pinned ECS version (e.g. `8.11`) |
| `event.category` | mapped from `artifact_type` | ECS categorization |
| `event.type` | mapped from `artifact_type` | ECS type |
| `event.action` | `timestamp_desc` / parser | |
| `host.*` | parser fields / bundle manifest | name, os, ip |
| `user.*` | parser fields | name, id, domain |
| `process.*` | parser fields | name, pid, command_line, parent.* |
| `source.*` / `destination.*` | parser fields | ip, port, domain |
| `file.*` | parser fields | path, hash.* |
| `threat.technique.id` | OSSEM / Sigma tag → ATT&CK | technique id |
| `threat.tactic.name` | OSSEM | tactic |
| `message` | `message` | preserved |
| `citadel.raw` | `raw` | original record retained for re-mapping |

## Mapping sources (config-driven)
- ECS field maps per `artifact_type`.
- OSSEM relationships for ATT&CK enrichment.
- Sigma-tag → ATT&CK technique table.

## Enrichment hooks (planned)
GeoIP, ASN, reverse-DNS on `source.ip` / `destination.ip`.
