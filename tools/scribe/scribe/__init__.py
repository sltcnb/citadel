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


def render_docx(data, tpl=None, language=None):
    """Lazy wrapper — imports python-docx only when DOCX is actually requested,
    so the package stays importable without the optional dependency."""
    from .docx_render import render_docx as _impl

    return _impl(data, tpl, language)


__all__ = [
    "render_markdown",
    "render_html",
    "render_docx",
    "TEMPLATE_DEFAULTS",
    "merge_template",
    "proofread",
]
