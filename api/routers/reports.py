"""
Investigation report endpoints.

Gathers case data (pinned/flagged events, MITRE coverage, watchlist + detection
runs, analyst notes, AI report, and activity aggregates) and hands it to the
**Scribe** engine (tools/scribe) for rendering. This module is the data + HTTP
layer only — all rendering/layout lives in the `scribe` package.
"""

from __future__ import annotations

import json
import logging

import redis_keys as rk
from auth.dependencies import require_admin, require_case_access
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from services.elasticsearch import _request as es_req

from config import get_redis

# Rendering engine lives in the Scribe tool package (pip-installed into the image).
from scribe import (
    TEMPLATE_DEFAULTS,
    merge_template,
    proofread,
    render_docx,
    render_docx_document,
    render_html,
    render_html_document,
    render_markdown,
    render_markdown_document,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["reports"])

_REPORT_TEMPLATE_KEY = "fo:report_template"


def _load_template() -> dict:
    try:
        raw = get_redis().get(_REPORT_TEMPLATE_KEY)
        stored = json.loads(raw) if raw else None
    except Exception:
        stored = None
    return merge_template(stored)


# ── Data gathering (ES / Redis) ───────────────────────────────────────────────


def _fetch_events(case_id: str, field: str, size: int = 200) -> list[dict]:
    body = {
        "query": {"term": {field: True}},
        "size": size,
        "sort": [{"timestamp": {"order": "asc", "unmapped_type": "keyword", "missing": "_last"}}],
    }
    try:
        r = es_req("POST", f"/fo-case-{case_id}-*/_search", body)
        return [h["_source"] for h in r.get("hits", {}).get("hits", [])]
    except Exception:
        return []


def _fetch_saved_searches(case_id: str, per_query_samples: int = 5) -> list[dict]:
    """Each saved search, RE-RUN now, with its exact hit count + a few samples.
    Saved searches store only the query string, so the report shows live results
    (a no-LLM analyst deliverable: 'here's what each bookmarked query matches')."""
    try:
        raw = get_redis().get(rk.case_saved_searches(case_id))
        searches = json.loads(raw) if raw else []
    except Exception:
        return []
    out: list[dict] = []
    for s in searches[:25]:
        q = (s.get("query") or "").strip()
        entry = {"name": s.get("name") or q or "(unnamed)", "query": q, "count": 0, "samples": []}
        if q:
            body = {
                "size": per_query_samples,
                "track_total_hits": True,  # exact count, no 10k cap
                "query": {"query_string": {"query": q[:512], "default_operator": "AND", "lenient": True}},
                "sort": [{"timestamp": {"order": "desc", "unmapped_type": "keyword", "missing": "_last"}}],
                "_source": ["timestamp", "artifact_type", "message", "host.hostname", "user.name"],
            }
            try:
                r = es_req("POST", f"/fo-case-{case_id}-*/_search", body)
                hits = r.get("hits", {})
                entry["count"] = (hits.get("total") or {}).get("value", 0)
                entry["samples"] = [h.get("_source", {}) for h in hits.get("hits", [])]
            except Exception:
                pass
        out.append(entry)
    return out


def _fetch_killchains(case_id: str, max_anchors: int = 5, window_minutes: int = 60) -> list[dict]:
    """Correlation view: assemble the reverse kill chain around the top flagged
    events (confirmed-bad anchors). Bounded + best-effort so a slow/empty case
    never blocks the report."""
    try:
        from services.killchain import assemble_chain
    except Exception:
        return []
    anchors = _fetch_events(case_id, "is_flagged", size=max_anchors)
    chains: list[dict] = []
    for ev in anchors[:max_anchors]:
        fo_id = ev.get("fo_id")
        if not fo_id:
            continue
        try:
            chain = assemble_chain(case_id, fo_id=fo_id, window_minutes=window_minutes)
        except Exception:
            continue
        steps = chain.get("steps") or []
        if not steps:
            continue
        chains.append(
            {
                "anchor": chain.get("anchor") or {"fo_id": fo_id},
                "tactics_covered": chain.get("tactics_covered") or [],
                "steps": steps,
            }
        )
    return chains


def _fetch_mitre(case_id: str) -> dict:
    body = {
        "size": 0,
        "query": {"exists": {"field": "mitre.id"}},
        "aggs": {
            "by_technique": {
                "terms": {"field": "mitre.id.keyword", "size": 100},
                "aggs": {
                    "top_name": {"terms": {"field": "mitre.technique.keyword", "size": 1}},
                    "top_tactic": {"terms": {"field": "mitre.tactic", "size": 1}},
                },
            },
        },
    }
    try:
        res = es_req("POST", f"/fo-case-{case_id}-*/_search", body)
    except Exception:
        return {"techniques": []}
    techniques = []
    for b in res.get("aggregations", {}).get("by_technique", {}).get("buckets", []):
        names = b.get("top_name", {}).get("buckets", [])
        tactics = b.get("top_tactic", {}).get("buckets", [])
        techniques.append(
            {
                "id": b["key"],
                "name": names[0]["key"] if names else b["key"],
                "tactic": tactics[0]["key"] if tactics else "",
                "count": b["doc_count"],
            }
        )
    return {"techniques": techniques}


def _agg_terms(case_id: str, field: str, size: int = 12) -> list[dict]:
    body = {"size": 0, "aggs": {"t": {"terms": {"field": field, "size": size}}}}
    try:
        r = es_req("POST", f"/fo-case-{case_id}-*/_search", body)
        return [
            {"value": b.get("key"), "count": b.get("doc_count", 0)}
            for b in r.get("aggregations", {}).get("t", {}).get("buckets", [])
            if b.get("key") not in (None, "")
        ]
    except Exception:
        return []


def _fetch_timeline(case_id: str) -> list[dict]:
    """Events-per-day for the 'events over time' chart (last ~30 active days)."""
    body = {
        "size": 0,
        "aggs": {
            "t": {
                "date_histogram": {
                    "field": "timestamp",
                    "calendar_interval": "day",
                    "min_doc_count": 1,
                }
            }
        },
    }
    try:
        r = es_req("POST", f"/fo-case-{case_id}-*/_search", body)
        buckets = r.get("aggregations", {}).get("t", {}).get("buckets", [])
        return [
            {"value": (b.get("key_as_string") or "")[:10], "count": b.get("doc_count", 0)}
            for b in buckets
        ][-30:]
    except Exception:
        return []


def _fetch_cti(case_id: str, size: int = 60) -> list[dict]:
    """Enriched threat-intel matches: one row per indicator with context
    (hits, last seen, feed, threat type) + cross-case 'seen before' history."""
    body = {
        "size": size,
        "query": {"term": {"artifact_type": "cti_match"}},
        "sort": [{"cti_match.match_count": {"order": "desc", "unmapped_type": "long"}}],
        "_source": ["timestamp", "cti_match"],
    }
    try:
        r = es_req("POST", f"/fo-case-{case_id}-*/_search", body)
        hits = r.get("hits", {}).get("hits", [])
    except Exception:
        return []
    out = []
    for h in hits:
        src = h.get("_source", {}) or {}
        cm = src.get("cti_match") or {}
        if not cm.get("ioc_value"):
            continue
        out.append(
            {
                "value": cm.get("ioc_value"),
                "type": cm.get("ioc_type", ""),
                "count": cm.get("match_count") or 0,
                "last_seen": src.get("timestamp", ""),
                "first_seen": "",
                "feed": cm.get("feed_name", ""),
                "threat": cm.get("threat_type", ""),
            }
        )
    # Cross-case memory — "have we seen this IOC in OTHER cases?" (best-effort).
    try:
        from services import pilot_memory as pm

        vals = [o["value"] for o in out if o.get("value")]
        seen = {s.get("value"): s for s in (pm.seen_before(vals, current_case=case_id) or [])}
        for o in out:
            s = seen.get(o["value"])
            if s:
                o["prior_cases"] = s.get("count") or len(s.get("cases", []) or [])
    except Exception:
        pass
    return out


def _fetch_aggregates(case_id: str) -> dict:
    """Activity aggregates for the graphical overview — each agg is best-effort
    (text fields fall back to .keyword; failures just omit that chart)."""
    agg: dict = {}
    agg["artifact_types"] = _agg_terms(case_id, "artifact_type")
    agg["top_src_ips"] = _agg_terms(case_id, "network.src_ip") or _agg_terms(
        case_id, "network.src_ip.keyword"
    )
    agg["severity"] = _agg_terms(case_id, "level") or _agg_terms(case_id, "level.keyword")
    agg["timeline"] = _fetch_timeline(case_id)
    agg["cti"] = _fetch_cti(case_id)
    try:
        c = es_req("GET", f"/fo-case-{case_id}-*/_count")
        agg["total_events"] = c.get("count", 0)
    except Exception:
        pass
    return agg


def _fetch_redis_json(key: str) -> dict:
    raw = get_redis().get(key)
    if not raw:
        return {}
    try:
        return json.loads(raw.decode() if isinstance(raw, bytes) else raw)
    except Exception:
        return {}


def _fetch_notes(case_id: str) -> str:
    raw = get_redis().get(f"case:{case_id}:notes")
    if not raw:
        return ""
    s = raw.decode() if isinstance(raw, bytes) else raw
    try:
        return json.loads(s).get("body", s) if s.startswith("{") else s
    except Exception:
        return s


def _fetch_ai_report(case_id: str) -> dict | None:
    return _fetch_redis_json(f"case:{case_id}:ai:report") or None


def _fetch_module_runs(case_id: str) -> list[dict]:
    """Completed analysis-module runs (hayabusa/yara/cti_match/…) + hit counts,
    so the report shows what scanners ran and what they found."""
    try:
        from services import module_runs as run_svc

        runs = run_svc.list_case_module_runs(case_id) or []
    except Exception:
        return []
    out = []
    for r in runs:
        if r.get("status") not in ("COMPLETED", "completed", None):
            # still surface running/failed, but completed first
            pass
        out.append(
            {
                "module_id": r.get("module_id"),
                "status": r.get("status"),
                "total_hits": r.get("total_hits", 0),
                "hits_by_level": r.get("hits_by_level", {}),
                "started_at": r.get("started_at") or r.get("created_at", ""),
            }
        )
    out.sort(key=lambda m: -(m.get("total_hits") or 0))
    return out


def _fetch_findings(case_id: str) -> dict:
    """The unified findings store — every analysis surface's saved output
    (IOC / anomaly / MITRE / kill-chain / entity / process-tree / module /
    co-pilot / manual), so the report covers them all from one source."""
    try:
        from services import findings as fnd

        listing = fnd.list_findings(case_id, size=1000)
        summary = fnd.findings_summary(case_id)
        return {
            "items": listing.get("findings", []),
            "total": listing.get("total", 0),
            "by_kind": summary.get("by_kind", {}),
            "by_severity": summary.get("by_severity", {}),
        }
    except Exception:
        return {"items": [], "total": 0, "by_kind": {}, "by_severity": {}}


def _build_report_data(case: dict, case_id: str) -> dict:
    from datetime import UTC, datetime

    pinned = _fetch_events(case_id, "is_pinned")
    flagged = _fetch_events(case_id, "is_flagged")
    modules = _fetch_module_runs(case_id)
    saved = _fetch_saved_searches(case_id)
    killchains = _fetch_killchains(case_id)
    notes = _fetch_notes(case_id)
    ai_report = _fetch_ai_report(case_id)
    aggregates = _fetch_aggregates(case_id)
    findings = _fetch_findings(case_id)

    # Manifest — a plain-language inventory of EXACTLY what this report was built
    # from, so "based idk what" becomes "based on these N inputs". Rendered as the
    # report's opening block.
    modules_with_hits = [m for m in modules if int(m.get("total_hits") or 0) > 0]
    manifest = {
        "generated_at": datetime.now(UTC).isoformat(),
        "flagged_count": len(flagged),
        "pinned_count": len(pinned),
        "module_run_count": len(modules),
        "module_hit_run_count": len(modules_with_hits),
        "saved_search_count": len([s for s in saved if s.get("query")]),
        "killchain_count": len(killchains),
        "total_events": (aggregates or {}).get("total_events", 0),
        "findings_count": findings.get("total", 0),
        "findings_by_kind": findings.get("by_kind", {}),
        "has_ai": bool(ai_report and (ai_report.get("content") or "").strip()),
        "ai_model": (ai_report or {}).get("model_used", ""),
        "ai_generated_at": (ai_report or {}).get("generated_at", ""),
    }

    return {
        "case": case,
        "manifest": manifest,
        "findings": findings,
        "pinned": pinned,
        "flagged": flagged,
        "mitre": _fetch_mitre(case_id),
        "modules": modules,
        "saved_searches": saved,
        "killchains": killchains,
        "watchlist": _fetch_redis_json(f"fo:watchlist_runs:{case_id}"),
        "detections": _fetch_redis_json(rk.case_alert_run(case_id)),
        "notes": notes,
        "ai_report": ai_report,
        "aggregates": aggregates,
    }


def _safe_name(case: dict, case_id: str) -> str:
    return (case.get("name") or case_id).replace("/", "_")[:80]


def _recheck(data: dict) -> dict:
    """Run Scribe's proofread pass over the error-prone free-text (AI report +
    analyst notes) using the configured LLM, then return the cleaned data. Used
    when ?review=1. Best-effort — never raises, falls back to originals."""
    try:
        from routers.llm_config import _call_llm_with_system, _get_config

        cfg = _get_config(get_redis())
        if not cfg or not cfg.get("enabled", True):
            return data

        def _llm(system, user):
            return _call_llm_with_system(cfg, system, user, max_tokens=4000)

        ai = data.get("ai_report")
        if ai and (ai.get("content") or "").strip():
            ai = dict(ai)
            ai["content"] = proofread(ai["content"], _llm)
            data["ai_report"] = ai
        if (data.get("notes") or "").strip():
            data["notes"] = proofread(data["notes"], _llm)
    except Exception:
        logger.warning("report recheck failed; serving unreviewed", exc_info=True)
    return data


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/cases/{case_id}/report.md")
def report_markdown(case_id: str, review: bool = False, language: str | None = None, case: dict = Depends(require_case_access)):
    data = _build_report_data(case, case_id)
    if review:
        data = _recheck(data)
    md = render_markdown(data, _load_template(), language=language)
    return Response(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_safe_name(case, case_id)}-report.md"'},
    )


@router.get("/cases/{case_id}/report.html")
def report_html(case_id: str, review: bool = False, language: str | None = None, case: dict = Depends(require_case_access)):
    """Graphical, printable HTML — stat cards, bar charts, real tables."""
    data = _build_report_data(case, case_id)
    if review:
        data = _recheck(data)
    page = render_html(data, _load_template(), language=language)
    return Response(
        content=page,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{_safe_name(case, case_id)}-report.html"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/cases/{case_id}/report.pdf")
def report_pdf(case_id: str, review: bool = False, language: str | None = None, case: dict = Depends(require_case_access)):
    """Native PDF — renders the graphical HTML, then WeasyPrint → PDF (same
    layout as the HTML, no browser print step)."""
    try:
        from weasyprint import HTML  # type: ignore
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="PDF export unavailable — the WeasyPrint dependency is not installed in this build.",
        )
    data = _build_report_data(case, case_id)
    if review:
        data = _recheck(data)
    html = render_html(data, _load_template(), language=language)
    try:
        pdf = HTML(string=html).write_pdf()
    except Exception as exc:
        logger.warning("PDF render failed for case %s: %s", case_id, exc)
        raise HTTPException(status_code=500, detail=f"PDF render failed: {exc}")
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{_safe_name(case, case_id)}-report.pdf"'},
    )


@router.get("/cases/{case_id}/report.docx")
def report_docx(case_id: str, review: bool = False, language: str | None = None, case: dict = Depends(require_case_access)):
    """Native Word document (.docx) — built from the report data, not converted
    from HTML, so analysts can edit/co-sign in Office."""
    data = _build_report_data(case, case_id)
    if review:
        data = _recheck(data)
    try:
        blob = render_docx(data, _load_template(), language=language)
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="DOCX export unavailable — the python-docx dependency is not installed in this build.",
        )
    except Exception as exc:
        logger.warning("DOCX render failed for case %s: %s", case_id, exc)
        raise HTTPException(status_code=500, detail=f"DOCX render failed: {exc}")
    return Response(
        content=blob,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{_safe_name(case, case_id)}-report.docx"'},
    )


# ── AI LLM report export (the narrative deliverable, any format) ───────────────


def _load_ai_report(case_id: str) -> dict:
    """Fetch the stored AI LLM report doc, or raise 404."""
    try:
        raw = get_redis().get(f"case:{case_id}:ai:report")
        doc = json.loads(raw) if raw else None
    except Exception:
        doc = None
    if not doc or not (doc.get("content") or "").strip():
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="No AI report generated yet — click Generate first.")
    return doc


def _ai_report_meta(doc: dict) -> tuple[str, list[str]]:
    """(title, meta_lines) for the AI report export header."""
    title = "Investigation Report"
    meta = []
    if doc.get("generated_at"):
        meta.append(f"Generated {doc['generated_at'][:19].replace('T', ' ')} UTC")
    if doc.get("model_used"):
        meta.append(str(doc["model_used"]))
    if doc.get("language"):
        meta.append(str(doc["language"]).upper())
    m = doc.get("manifest") or {}
    bits = []
    if m.get("flagged_count") is not None:
        bits.append(f"{m['flagged_count']} flagged")
    if m.get("module_detections"):
        bits.append(f"{m['module_detections']} module detections")
    if m.get("ioc_lines"):
        bits.append(f"{m['ioc_lines']} IOC lines")
    if bits:
        meta.append("based on " + ", ".join(bits))
    return title, meta


@router.get("/cases/{case_id}/ai/report.md")
def ai_report_md(case_id: str, case: dict = Depends(require_case_access)):
    doc = _load_ai_report(case_id)
    title, meta = _ai_report_meta(doc)
    md = render_markdown_document(title, doc["content"], meta)
    return Response(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_safe_name(case, case_id)}-ai-report.md"'},
    )


@router.get("/cases/{case_id}/ai/report.html")
def ai_report_html(case_id: str, case: dict = Depends(require_case_access)):
    doc = _load_ai_report(case_id)
    title, meta = _ai_report_meta(doc)
    page = render_html_document(title, doc["content"], meta)
    return Response(
        content=page,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{_safe_name(case, case_id)}-ai-report.html"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/cases/{case_id}/ai/report.pdf")
def ai_report_pdf(case_id: str, case: dict = Depends(require_case_access)):
    try:
        from weasyprint import HTML  # type: ignore
    except Exception:
        from fastapi import HTTPException

        raise HTTPException(status_code=503, detail="PDF export unavailable — WeasyPrint not installed in this build.")
    doc = _load_ai_report(case_id)
    title, meta = _ai_report_meta(doc)
    html = render_html_document(title, doc["content"], meta)
    try:
        pdf = HTML(string=html).write_pdf()
    except Exception as exc:
        from fastapi import HTTPException

        logger.warning("AI report PDF failed (case %s): %s", case_id, exc)
        raise HTTPException(status_code=500, detail=f"PDF render failed: {exc}")
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{_safe_name(case, case_id)}-ai-report.pdf"'},
    )


@router.get("/cases/{case_id}/ai/report.docx")
def ai_report_docx(case_id: str, case: dict = Depends(require_case_access)):
    doc = _load_ai_report(case_id)
    title, meta = _ai_report_meta(doc)
    try:
        blob = render_docx_document(title, doc["content"], meta)
    except ImportError:
        from fastapi import HTTPException

        raise HTTPException(status_code=503, detail="DOCX export unavailable — python-docx not installed in this build.")
    except Exception as exc:
        from fastapi import HTTPException

        logger.warning("AI report DOCX failed (case %s): %s", case_id, exc)
        raise HTTPException(status_code=500, detail=f"DOCX render failed: {exc}")
    return Response(
        content=blob,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{_safe_name(case, case_id)}-ai-report.docx"'},
    )


# ── Report template admin ─────────────────────────────────────────────────────


class ReportTemplateIn(BaseModel):
    title_prefix: str = "Investigation report"
    header_md: str = ""
    footer_md: str = "_Generated by Citadel_"
    max_flagged: int = 50
    sections: dict = {}


@router.get("/admin/report-template", dependencies=[Depends(require_admin)])
def get_report_template():
    return _load_template()


@router.put("/admin/report-template", dependencies=[Depends(require_admin)])
def set_report_template(body: ReportTemplateIn):
    sections = dict(TEMPLATE_DEFAULTS["sections"])
    for k, v in (body.sections or {}).items():
        if k in sections:
            sections[k] = bool(v)
    tpl = {
        "title_prefix": (body.title_prefix or "Investigation report")[:120],
        "header_md": (body.header_md or "")[:4000],
        "footer_md": (body.footer_md or "")[:1000],
        "max_flagged": min(max(1, body.max_flagged), 500),
        "sections": sections,
    }
    get_redis().set(_REPORT_TEMPLATE_KEY, json.dumps(tpl))
    return tpl


@router.delete("/admin/report-template", dependencies=[Depends(require_admin)])
def reset_report_template():
    get_redis().delete(_REPORT_TEMPLATE_KEY)
    return _load_template()
