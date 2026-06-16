from scribe import TEMPLATE_DEFAULTS, merge_template, render_html, render_markdown

_DATA = {
    "case": {"name": "DataX", "company": "Iliad"},
    "pinned": [
        {
            "timestamp": "2026-06-09T07:17:04Z",
            "artifact_type": "audit_event",
            "host": {"hostname": "master2"},
            "message": "ANOM_ABEND nginx sig=11",
        }
    ],
    "flagged": [],
    "mitre": {"techniques": [{"id": "T1498", "name": "Network DoS", "tactic": "Impact", "count": 42}]},
    "watchlist": {},
    "detections": {},
    "notes": "## Findings\n\n| Host | Status |\n|------|--------|\n| master2 | crashed |\n",
    "ai_report": {"content": "# Summary\nnginx segfaulted.", "model_used": "qwen"},
    "aggregates": {
        "total_events": 19778817,
        "artifact_types": [{"value": "access_log", "count": 11459822}],
        "top_src_ips": [{"value": "213.36.7.14", "count": 1424}],
        "severity": [{"value": "high", "count": 17181}],
        "cti": [{"value": "137.184.32.56", "count": 62}],
    },
}


def test_merge_template_defaults():
    t = merge_template(None)
    assert t["sections"]["overview"] is True
    t2 = merge_template({"max_flagged": 9999, "sections": {"flagged": False}})
    assert t2["max_flagged"] == 500 and t2["sections"]["flagged"] is False


def test_markdown_has_overview_and_evidence():
    md = render_markdown(_DATA, merge_template(None))
    assert "Activity overview" in md
    assert "213.36.7.14" in md
    assert "ANOM_ABEND" in md


def test_html_is_graphical_and_parses_tables():
    h = render_html(_DATA, merge_template(None))
    assert "bar-fill" in h            # bar charts
    assert 'class="card"' in h        # stat cards
    assert "table class=evt" in h     # event table
    assert "<th>Host</th>" in h.replace("\n", "")   # pipe table from notes parsed
    assert "<td>master2</td>" in h.replace("\n", "")


def test_section_toggle_off():
    t = merge_template({"sections": {"overview": False}})
    assert "Activity overview" not in render_markdown(_DATA, t)


def test_defaults_constant_stable():
    assert "overview" in TEMPLATE_DEFAULTS["sections"]
