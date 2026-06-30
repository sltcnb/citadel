# citadel_contracts — The Shared Contract Package

> The only thing the tools are allowed to import from each other.

**Status: built · shared** — the pip-installable package every Citadel tool depends on.

`citadel_contracts` is how the suite stays standalone-first: tools never import each other's internals; they import *this* package and exchange data through its types and validators. It is the Python embodiment of the JSON schemas in [`../../contracts/`](../../contracts/). It is dependency-free (Python 3.11+; `jsonschema` optional for full schema validation) and has **no `brick.yaml`** — it is a library, not a pipeline stage.

## What it exports

**Parser contract** — `BasePlugin` (the Babel parser ABC: `can_handle → setup → parse → teardown`), `PluginContext`, `PluginError`/`PluginParseError`/`PluginFatalError`, `STRUCTURED_ARTIFACTS` (types that must carry a `raw` record), `classify_os()`, `iso_z()`.

**ForensicEvent validation** — `validate_forensic_event(event, schema_path=None, require_z=True) → (ok, error)` and `is_valid_forensic_event(...)`. Enforces required `timestamp` (ISO-8601 **Z**) + `message`, and `raw` for structured types.

**Anvil module contract** — `BaseModule` (analyzer ABC), `Result` (findings + artifacts + metrics, with `.to_dict()`).

**Finding schema** — `Finding` dataclass, `make_finding()`, `SEVERITIES`, `KINDS` (ioc, anomaly, mitre, killchain, entity, proctree, module, copilot, baseline, manual).

**Capability advertisement** — `CapabilityManifest`, `Capability`, `InputField`, `FIELD_TYPES`, `PLATFORMS`, `manifest_from_dict()`, `register_capability()`, `capabilities_redis_key()` — the schema behind every tool's `capabilities.yaml`.

**Declarative mapping engine** — `MappingSpec`, `apply_mapping()`, `detect_spec()`, `iter_records()`, `render_template()`, `register_transform()` — YAML-declared mapping of structured logs to `ForensicEvent`.

**Authoring SDK** — the `@parser` decorator, the `event(...)` builder, and `Ctx` (cheap `.text()`/`.lines()`/`.json()`/`.jsonl()` readers).

**Observability** — `setup_json_logging()`, `JsonFormatter`, `attach_redis_logs()`, `RedisLogHandler`, `log_stream_key()`, `tool_logger()` — shared structured logging + capped Redis log streams (`citadel:logs:<service>`).

## How a tool uses it

```toml
# pyproject.toml
citadel-contracts = { path = "../../tools/citadel_contracts" }
```

```python
from citadel_contracts import BasePlugin, validate_forensic_event, event
```

Subclass `BasePlugin` and implement `can_handle()` + `parse()`; yield `ForensicEvent`-shaped dicts (or build them with `event(...)`). The Babel loader discovers the subclass and validates each event against the contract before indexing.

## Relationship to `contracts/`

The repo-root [`contracts/`](../../contracts/) directory holds the language-neutral schemas (`forensic_event.schema.json`, `bundle_manifest.schema.json`, `brick.schema.json`, `ecs_extension.md`, `bus_topics.md`, `collector.proto`). `citadel_contracts` is the Python implementation tools link against; `validate_forensic_event` checks events against `forensic_event/v1.json`.
