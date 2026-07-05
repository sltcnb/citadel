# Anvil — Analysis Runner

> Forge raw evidence into findings: run heavy analyzers in a sandbox, chain them in a DAG.

**Status: built** — typed module contract, sandboxed execution, DAG pipeline.

Anvil runs deep analysis modules over case evidence. Each module is a typed `BaseModule` that takes an artifact (plus parameters) and returns a structured `Result` — `hits` (severity-rated findings with optional MITRE technique), `artifacts` (extracted files/reports), and `metrics`. Modules compose into a DAG so a downstream analyzer can consume an upstream module's output.

## Pipeline position

```
Rosetta / store ──▶ Anvil (module) ──findings──▶ timeline / report
```

Post-ingest analysis stage: after artifacts are in the case, Anvil performs the deeper work (memory analysis, malware triage, YARA hunting, process trees, persistence sweeps).

## Inputs → Outputs

- **Inputs** — a raw artifact (memory image, EVTX dir, PE, document, …) + a module name + per-module parameters.
- **Outputs** — a typed `Result` (`result.schema.json`): `hits[]` (severity `critical|high|medium|low|informational`, title, description, file, techniques), `artifacts[]` (`file|report|extracted|log`), `metrics{}`. Findings surface on the timeline as events.
- **Dependencies** — Redis (queue, cancel flags, per-run log streaming at `fo:module_log:<run_id>`).

## Modules

Built-in analyzers ship as `*_module.py` here: access-log analysis, capa, de4dot, exiftool, floss, grep search, malwoverview, oletools / OLE analysis, PE analysis, strings / strings analysis. Heavier engines (Volatility3, Hayabusa, RegRipper, YARA) are wired through the module registry (`api/modules_registry/*.yaml`).

The live module set is **dynamic**: built-ins are discovered at build, custom modules self-register via Redis (`fo:capabilities:anvil`), and the `run_module` capability's options are filled from the live registry — so a new module appears in the UI with no manifest edit.

## Contracts

From `brick.yaml` (v1.0.0, status **built**):

- **Consumes** — raw artifacts: `application/octet-stream`, any filename (memory images, EVTX dirs, PEs, documents).
- **Produces** — findings as events, schema `https://citadel.dfir/contracts/forensic_event/v1.json` (ForensicEvent v1), artifact type `module_finding`. The per-run module output shape is [`result.schema.json`](result.schema.json) in this repo.

Contract schemas and the `BaseModule` / `Result` Python types are versioned in the `citadel_contracts` package ([github.com/sltcnb/citadel-contracts](https://github.com/sltcnb/citadel-contracts)).

## Install

```bash
pip install git+https://github.com/sltcnb/citadel-contracts   # BaseModule / Result types
pip install -e .
```

In the monorepo, `base.py` resolves a sibling `citadel_contracts` checkout automatically; in a standalone clone install it from the repo above. Individual modules shell out to their engines (`capa`, `floss`, `exiftool`, `de4dot`, `malwoverview`, …) — the matching binary must be on `PATH` for that module to run.

## Configuration

| Variable | Default | Used by |
|---|---|---|
| `MINIO_BUCKET` | `forensics-cases` | most modules — object-store bucket for artifact fetch / result upload |
| `VT_API_KEY` | *(unset, optional)* | `malwoverview` module only |

Everything else is passed as per-run module parameters, not environment.

## Run / use

```bash
anvil list                       # list available modules (also the brick health check)
anvil run volatility3 -a mem.raw # run a module against an artifact
```

In the platform, modules execute inside the sluice-worker `modules` queue via a sandboxed harness (`tasks/_module_sandbox.py`: resource limits, env isolation, JSON-over-stdin).

## Tests

```bash
pytest test_artifacts.py test_base_module.py test_pipeline.py   # from the tool root
```

## In Citadel

The API exposes modules at `GET /modules` and dispatches runs to the worker; results attach to the case timeline and feed the report. Module DAGs let an analyzer pipeline (e.g. unpack → strings → IOC match) run as one unit.

See the `BaseModule` / `Result` contract in the `citadel_contracts` package ([github.com/sltcnb/citadel-contracts](https://github.com/sltcnb/citadel-contracts)) and [`result.schema.json`](result.schema.json).

## Part of the Citadel suite

Anvil is the deep-analysis stage of [Citadel](https://github.com/sltcnb/citadel). **Upstream:** artifacts arrive via [sluice](https://github.com/sltcnb/sluice) (worker/) after canonicalization by [rosetta](https://github.com/sltcnb/rosetta). **Downstream:** findings land on the case timeline and feed [pilot](https://github.com/sltcnb/pilot) and [scribe](https://github.com/sltcnb/scribe). Runtime service dependency (from `brick.yaml`): **Redis** — queue, cancel flags, per-run log streaming.
