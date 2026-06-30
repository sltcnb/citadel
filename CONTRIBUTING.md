# Contributing — adding a tool or parser

Citadel's interchangeability comes from one rule: **tools depend on contracts,
never on each other.** Cross a tool boundary only via a contract — a schema, a
`.proto`, a bus topic, or the `BasePlugin` / `BaseModule` ABCs in
[`citadel_contracts`](tools/citadel_contracts).

## Add a Babel parser (the common case)

A parser is any module that subclasses `citadel_contracts.BasePlugin` and yields
`ForensicEvent`s. Scaffold one from the cookiecutter template:

```bash
cookiecutter tools/babel/template     # → manifest.yaml + <name>_plugin.py + test
```

Implement `parse()` (yield dicts with the required `timestamp` + `message`),
declare `SUPPORTED_EXTENSIONS` / `SUPPORTED_MIME_TYPES` and `PLUGIN_PRIORITY`,
and drop the package under `tools/babel/`. The loader discovers it — no
registration. See `tools/babel/sdk/README.md`.

## Add a whole tool

1. New `tools/<name>/` (or its own repo), depending only on `citadel_contracts`
   + the schemas in `contracts/`.
2. Ship a `brick.yaml` declaring `consumes` / `produces` / `dependencies` /
   `health` (validated against `contracts/brick.schema.json`).
3. Emit `ForensicEvent` (validated by `citadel_contracts.validate_forensic_event`).
4. Register it in `tools/versions.yaml` (repo + pinned ref) and `tools/SUITE.yaml`.
5. Write a `tools/<name>/README.md` covering purpose, pipeline position, inputs,
   outputs, how to run standalone, and how it composes with Citadel.

## Rules

- Never `import` another tool's internals. Cross only via contracts.
- Timestamps are ISO-8601 **Z**; structured artifact types must carry `raw`.
- Add a test; `scripts/run_tests.sh` must stay green.

See the **Architecture** and **Develop, test & contribute** sections of the
[root README](README.md), plus the contract schemas in [`contracts/`](contracts/),
for the rules behind these conventions.
