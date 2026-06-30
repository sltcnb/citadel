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

## Run / use

`api/routers/reports.py` gathers case data and calls the engine; `scribe --version` is the health check. The standalone multi-format CLI is in progress (see capabilities below).

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
