# Contributing — adding a tool or parser

Citadel's interchangeability comes from one rule: **tools depend on contracts,
never on each other.**

## Add a Babel parser (the common case)

A parser is any module that subclasses `citadel_contracts.BasePlugin` and yields
ForensicEvents. Scaffold one from the cookiecutter template:

```bash
cookiecutter tools/babel/template     # → manifest.yaml + <name>_plugin.py + test
```

Implement `parse()` (yield dicts with required `timestamp` + `message`), declare
`SUPPORTED_EXTENSIONS` / `SUPPORTED_MIME_TYPES`, and drop the package under
`tools/babel/`. The loader discovers it — no registration. See
`tools/babel/sdk/README.md`.

## Add a whole tool

1. New repo (or `tools/<name>/`), depends only on `citadel_contracts` + the
   schemas in `contracts/`.
2. Ship a `brick.yaml` declaring `consumes` / `produces` / `dependencies` /
   `health` (validated against `contracts/brick.schema.json`).
3. Emit `ForensicEvent` (validated by `citadel_contracts.validate_forensic_event`).
4. Register it in `tools/versions.yaml` (repo + pinned ref) and `tools/SUITE.yaml`.

## Rules

- Never `import` another tool's internals. Cross only via contracts (schema,
  `.proto`, bus topic, or the `BasePlugin` ABC).
- Timestamps are ISO-8601 **Z**; structured artifact types must carry `raw`.
- Add a test; `scripts/run_tests.sh` must stay green.

See the [ADRs](adr/index.md) for the decisions behind these rules.
