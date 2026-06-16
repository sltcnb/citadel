# Scribe — Report Engine

> Turn a case into a shareable artifact for any audience.

**Status: active** — the rendering engine lives HERE (`scribe/render.py`), pip-installed
into the API image. `api/routers/reports.py` only gathers case data (ES/Redis) and calls
`render_markdown` / `render_html`. No duplicate rendering code in the API.

```python
from scribe import render_markdown, render_html, merge_template, TEMPLATE_DEFAULTS
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
