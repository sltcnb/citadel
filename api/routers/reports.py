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
from fastapi import APIRouter, Depends
from fastapi.responses import Response
from pydantic import BaseModel
from services.elasticsearch import _request as es_req

from config import get_redis

# Rendering engine lives in the Scribe tool package (pip-installed into the image).
from scribe import TEMPLATE_DEFAULTS, merge_template, proofread, render_html, render_markdown

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


def _build_report_data(case: dict, case_id: str) -> dict:
    return {
        "case": case,
        "pinned": _fetch_events(case_id, "is_pinned"),
        "flagged": _fetch_events(case_id, "is_flagged"),
        "mitre": _fetch_mitre(case_id),
        "modules": _fetch_module_runs(case_id),
        "watchlist": _fetch_redis_json(f"fo:watchlist_runs:{case_id}"),
        "detections": _fetch_redis_json(rk.case_alert_run(case_id)),
        "notes": _fetch_notes(case_id),
        "ai_report": _fetch_ai_report(case_id),
        "aggregates": _fetch_aggregates(case_id),
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
def report_markdown(case_id: str, review: bool = False, case: dict = Depends(require_case_access)):
    data = _build_report_data(case, case_id)
    if review:
        data = _recheck(data)
    md = render_markdown(data, _load_template())
    return Response(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_safe_name(case, case_id)}-report.md"'},
    )


@router.get("/cases/{case_id}/report.html")
def report_html(case_id: str, review: bool = False, case: dict = Depends(require_case_access)):
    """Graphical, printable HTML — stat cards, bar charts, real tables."""
    data = _build_report_data(case, case_id)
    if review:
        data = _recheck(data)
    page = render_html(data, _load_template())
    return Response(
        content=page,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{_safe_name(case, case_id)}-report.html"',
            "X-Content-Type-Options": "nosniff",
        },
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
