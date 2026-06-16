"""
Scribe — Citadel's report engine.

Pure rendering: turns a case data bundle into Markdown or a graphical, printable
HTML document. No Elasticsearch/Redis/HTTP here — the API (api/routers/reports.py)
gathers the data and the front door; Scribe owns *how it looks*.

    from scribe import render_markdown, render_html, TEMPLATE_DEFAULTS, merge_template

The data bundle is a dict:
    {
      "case": {...}, "pinned": [...], "flagged": [...],
      "mitre": {"techniques": [...]}, "watchlist": {...}, "detections": {...},
      "notes": "markdown", "ai_report": {...} | None,
      "aggregates": {"artifact_types": [...], "top_src_ips": [...],
                     "severity": [...], "cti": [...]},
    }
"""

from .render import (
    TEMPLATE_DEFAULTS,
    merge_template,
    proofread,
    render_html,
    render_markdown,
)

__all__ = ["render_markdown", "render_html", "TEMPLATE_DEFAULTS", "merge_template", "proofread"]
