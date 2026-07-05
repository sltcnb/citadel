# Scribe — Report Engine

> Turn a case into a shareable artifact for any audience.

**Status: active** — the rendering engine lives HERE (`scribe/render.py`), pip-installed
into the API image. `api/routers/reports.py` only gathers case data (ES/Redis) and calls
`render_markdown` / `render_html`. No duplicate rendering code in the API.

```python
from scribe import render_markdown, render_html, merge_template, TEMPLATE_DEFAULTS
```

## Pipeline position

```
case (timeline · detections · findings · notes) ──▶ Scribe ──▶ HTML / PDF / Markdown / DOCX
```

- **Inputs** — a Citadel case: gathered ES/Redis data (events, detections, CTI hits, flagged/pinned items, notes, AI report).
- **Outputs** — a shareable report (`artifact_type: report`) — graphical HTML (print-to-PDF), Markdown, DOCX; STIX/MISP/JSON planned.
- **Dependencies** — Elasticsearch.

## Contracts

| Direction | Contract | Schema |
|---|---|---|
| Consumes | a Citadel case (`application/json`) built from ForensicEvent v1 data | `https://citadel.dfir/contracts/forensic_event/v1.json` |
| Produces | `artifact_type: report` (documents — no event schema; `produces.schema: []`) | — |

Contracts are versioned in the [citadel-contracts](https://github.com/sltcnb/citadel-contracts)
repo (Python package `citadel_contracts`).

## Install

Normally pip-installed into the Citadel API image. Standalone clone:

```bash
git clone https://github.com/sltcnb/scribe && cd scribe
pip install -e .          # zero runtime dependencies (stdlib only)
```

## Configuration

No environment variables — verified: no `os.environ`/`getenv` in the package.
The engine is pure functions: everything is passed by the caller — case data as
arguments, branding/section toggles via `merge_template` over `TEMPLATE_DEFAULTS`,
and the optional proofread LLM as an injected `llm_call(system, user)` callable
(Scribe itself does no I/O and holds no credentials).

## Run / health

`api/routers/reports.py` gathers case data and calls the engine; `scribe --version` is the health check (from `brick.yaml`). The standalone multi-format CLI is in progress (see capabilities below).

## Tests

```bash
pip install -e '.[test]'
pytest tests/             # tests/test_render.py
```

## Capabilities
- [●] Markdown report
- [●] Graphical HTML report — stat cards, bar charts, real tables (print-to-PDF)
- [●] Activity overview aggregates (artifact types, top IPs, severity, CTI hits)
- [●] Org template + branding + section toggles
- [●] Flagged / pinned / MITRE / watchlist / detection / notes sections
- [●] Markdown pipe-table rendering (notes / AI report)
- [ ] Standalone CLI multi-format engine (PDF / STIX / MISP / JSON)
- [ ] Scheduled auto-report on case close
- [ ] Embedded timeline visualization

**Done when:** standalone CLI renders all formats; scheduled-on-close works.

## Part of the Citadel suite
Scribe is the last stage of the pipeline: it renders what the rest of the suite
produced. Runtime dependency (per `brick.yaml`): Elasticsearch (the caller
gathers case data from it). Upstream: the case timeline/detections/findings,
including [Pilot](https://github.com/sltcnb/pilot)'s AI investigation report.
Platform: [citadel](https://github.com/sltcnb/citadel) · Contracts:
[citadel-contracts](https://github.com/sltcnb/citadel-contracts).
