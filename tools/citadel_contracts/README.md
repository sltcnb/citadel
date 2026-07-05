# citadel_contracts — The Shared Contract Package

> The only thing the tools are allowed to import from each other.

**Status: built · shared** — the pip-installable package every Citadel tool depends on.

`citadel_contracts` is how the suite stays standalone-first: tools never import each other's internals; they import *this* package and exchange data through its types and validators. It is the Python embodiment of the suite's language-neutral schemas (see [below](#the-language-neutral-schemas)), which are vendored into this repo from the platform monorepo, [github.com/sltcnb/citadel](https://github.com/sltcnb/citadel). It is dependency-free (Python 3.11+; `jsonschema` optional for full schema validation) and has **no `brick.yaml`** — it is a library, not a pipeline stage.

## Install

```bash
pip install git+https://github.com/sltcnb/citadel-contracts
# or, for development:
git clone https://github.com/sltcnb/citadel-contracts
pip install -e citadel-contracts
```

The core validator has zero dependencies; add the `validate` extra (`pip install "citadel-contracts[validate]"`) for full JSON-Schema validation via `jsonschema>=4`.

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
# pyproject.toml — inside the Citadel platform monorepo (path dependency)
citadel-contracts = { path = "../../tools/citadel_contracts" }

# pyproject.toml — standalone tool repo (git dependency)
citadel-contracts = { git = "https://github.com/sltcnb/citadel-contracts" }
```

```python
from citadel_contracts import BasePlugin, validate_forensic_event, event
```

Subclass `BasePlugin` and implement `can_handle()` + `parse()`; yield `ForensicEvent`-shaped dicts (or build them with `event(...)`). The Babel loader discovers the subclass and validates each event against the contract before indexing.

## The language-neutral schemas

Anything that crosses a tool boundary in the suite is defined by these files. They are versioned in the platform monorepo and are being vendored into this repo (under `contracts/`) so it stands alone as the single contract source:

| File | Purpose |
|------|---------|
| `forensic_event.schema.json` | The canonical event a Babel parser yields, before Rosetta enriches it to full ECS. |
| `ecs_extension.md` | The ECS v8 + OSSEM fields Rosetta adds on top of a ForensicEvent. |
| `bundle_manifest.schema.json` | The portable evidence bundle Talon hands to Sluice (`manifest.json` inside `bundle/`). |
| `brick.schema.json` | The per-tool manifest declaring inputs, outputs, schema versions, deps, health. |
| `collector.proto` | The gRPC service between the Talon remote agent and Sluice/Citadel. |
| `bus_topics.md` | The Redis-Streams/NATS/Kafka topic contract for the async pipeline. |

`citadel_contracts` is the Python implementation tools link against: `validate_forensic_event` enforces the load-bearing ForensicEvent rules in plain Python, and checks the full `forensic_event` JSON Schema when `jsonschema` is installed and a `schema_path` is passed.

## Tests

```bash
pytest test_validator.py   # or: pytest .
```

---

Part of the **[Citadel](https://github.com/sltcnb/citadel)** DFIR suite — every Citadel tool depends on this package.
