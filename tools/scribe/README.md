# Scribe — Report Engine

> Turn a case into a shareable artifact for any audience.

**Status: partial** (rendering lives in `api/routers/reports.py` + `export.py` today; this tool extracts a standalone multi-format engine.)

## Standalone
```
scribe report --case CASE_ID -f pdf -o report.pdf
```

## Capabilities
- [●] Markdown report
- [●] Org template + branding + section toggles
- [●] Flagged / pinned / MITRE / watchlist / detection / notes sections
- [●] LLM-assisted executive summary
- [●] Multi-language output
- [●] Browser print-to-PDF
- [ ] Standalone multi-format engine (HTML / PDF / STIX / MISP / JSON)
- [ ] Scheduled auto-report on case close
- [ ] Embedded timeline + chart visualizations

**Done when:** standalone CLI renders all formats; scheduled-on-close works.
