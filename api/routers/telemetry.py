"""Telemetry — the read path over ``citadel-telemetry-*``, plus browser intake.

Two routers, mounted separately in ``main.py``:

* ``router``       — ``POST /telemetry/ui``. Unauthenticated by design: a render
  crash on the login page, or a chunk that failed to load before a token exists,
  is exactly the failure we most need reported. Bounded instead: a strict
  payload model, hard field truncation, and a per-IP rate limit.
* ``admin_router`` — ``GET /admin/telemetry/*``. The aggregations that turn a
  pile of events into "here is what to fix next": which routes fail, which are
  slow, which parsers break, what the LLM costs, what the browser choked on.

Everything here reads the index the shared sink in
``citadel_contracts.telemetry`` writes to. If telemetry is disabled or
Elasticsearch is down, these endpoints return empty results rather than errors —
observability going missing must not look like the platform being broken.
"""

from __future__ import annotations

import logging
import urllib.error

from citadel_contracts.telemetry import (
    INDEX_PATTERN,
    get_sink,
    record_ui_event,
)
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from services import telemetry_contract as contract
from services.elasticsearch import es_request

from config import get_redis, settings
from routers.auth import _resolve_client_ip

logger = logging.getLogger(__name__)

# Router-private, like collab.py's and pilot_settings.py's keys. Deliberately
# NOT in redis_keys: that module is duplicated between api/ and the Sluice
# worker, and the two copies only agree because every key in them is shared.
# Nothing outside this router ever writes this one.
_UI_RATELIMIT_KEY = "fo:ratelimit:telemetry_ui:{ip}"

router = APIRouter(tags=["telemetry"])
admin_router = APIRouter(tags=["admin"])

_SEARCH_PATH = f"/{INDEX_PATTERN}/_search?ignore_unavailable=true&allow_no_indices=true"

# The envelope every event carries, regardless of what any component advertises
# (mirrors citadel_contracts.telemetry's index template).
_ENVELOPE_FIELDS = frozenset(
    {
        "service", "kind", "event", "outcome", "duration_ms",
        "case_id", "correlation_id", "host", "version",
    }
)


def _search(body: dict) -> dict:
    """Run one telemetry search. An unreachable/empty index reads as no data."""
    try:
        return es_request("POST", _SEARCH_PATH, body)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        logger.warning("telemetry search failed: %s", exc)
        return {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("telemetry search unavailable: %s", exc)
        return {}


def declaration() -> contract.MergedTelemetry:
    """Every component's telemetry advertisement, merged.

    Reuses the tools router's cached aggregation, so a manifest change — a file
    edit, or a component re-registering itself in Redis — reaches this within
    that cache's TTL, with no restart and no code change here.
    """
    from routers.tools import _aggregate_cached

    try:
        return contract.merged(_aggregate_cached())
    except Exception as exc:  # noqa: BLE001 — no manifests must not 500 the page
        logger.warning("telemetry declarations unavailable: %s", exc)
        return contract.MergedTelemetry()


def _range(hours: int) -> dict:
    return {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}


def _buckets(aggs: dict, *path: str) -> list[dict]:
    """Walk a nested aggregation response, tolerating anything missing."""
    node: dict = aggs or {}
    for key in path:
        node = (node or {}).get(key) or {}
    return node.get("buckets") or []


# ── Browser intake ────────────────────────────────────────────────────────────


class UIErrorReport(BaseModel):
    """What the frontend is allowed to report. Deliberately small and typed —
    this endpoint is reachable unauthenticated, so nothing here is free-form
    enough to be used as a log-injection or storage-exhaustion vector."""

    event: str = Field(default="ui_error", max_length=64)
    message: str = Field(default="", max_length=2000)
    stack: str = Field(default="", max_length=8000)
    route: str = Field(default="", max_length=300)
    component: str = Field(default="", max_length=120)
    source: str = Field(default="", max_length=64)
    app_version: str = Field(default="", max_length=64)


def _ui_client_ip(request: Request) -> str:
    direct = request.client.host if request.client else "unknown"
    return _resolve_client_ip(
        request.headers.get("X-Forwarded-For"), direct, settings.TRUSTED_PROXY_HOPS
    )


def _ui_rate_limited(request: Request) -> bool:
    """Fixed 60-second window per client IP. Fails OPEN when Redis is down —
    losing an error report is worse than accepting a few extra."""
    limit = settings.TELEMETRY_UI_RATE_LIMIT
    if limit <= 0:
        return True
    try:
        r = get_redis()
        key = _UI_RATELIMIT_KEY.format(ip=_ui_client_ip(request))
        count = r.incr(key)
        if count == 1:
            r.expire(key, 60)
        return count > limit
    except Exception:  # noqa: BLE001
        return False


@router.post("/telemetry/ui", status_code=202)
def report_ui_error(body: UIErrorReport, request: Request):
    """Record a browser-side failure (render crash, unhandled rejection, 5xx).

    Returns 202 whether or not the event was stored — the browser has nothing
    useful to do with a failure here, and a retry loop over the error reporter
    is a good way to turn one bug into an outage.
    """
    if _ui_rate_limited(request):
        return {"recorded": False, "reason": "rate_limited"}
    actor = ""
    try:
        from auth.service import decode_token

        header = request.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            actor = decode_token(header[7:]).get("sub") or ""
    except Exception:  # noqa: BLE001 — an anonymous report is still worth having
        actor = ""
    record_ui_event(
        body.event or "ui_error",
        message=body.message,
        stack=body.stack,
        route=body.route,
        component=body.component,
        source=body.source,
        app_version=body.app_version,
        user_agent=request.headers.get("User-Agent", ""),
        user=actor,
    )
    return {"recorded": True}


# ── Admin read path ───────────────────────────────────────────────────────────


@admin_router.get("/admin/telemetry/health")
def telemetry_health():
    """Is telemetry actually working? Counters from the in-process sink plus the
    document count in the index — the two ways to notice it silently stopped."""
    sink = get_sink()
    health = sink.health() if sink is not None else {"enabled": False}
    docs = None
    try:
        res = es_request("GET", f"/{INDEX_PATTERN}/_count?ignore_unavailable=true")
        docs = res.get("count")
    except Exception:  # noqa: BLE001
        docs = None
    return {
        "sink": health,
        "index_pattern": INDEX_PATTERN,
        "documents": docs,
        "retention_days": settings.TELEMETRY_RETENTION_DAYS,
        "sample_rate": settings.TELEMETRY_SAMPLE_RATE,
        # Note the caveat: with multiple uvicorn workers each process has its own
        # sink, so `sink` describes THIS worker only. `documents` is cluster-wide.
        "note": "sink counters are per-process; document count is cluster-wide",
    }


@admin_router.get("/admin/telemetry/summary")
def telemetry_summary(hours: int = Query(24, ge=1, le=24 * 90)):
    """Every panel every deployed component advertises, in one query.

    There is nothing tool-shaped in this function. The panels, the fields they
    group by and the metrics they compute all come from ``telemetry:`` blocks
    in the components' own ``capabilities.yaml``. Remove a tool and its panels
    go with it; add one and its panels appear.
    """
    decl = declaration()
    if not decl.panels:
        return {
            "window_hours": hours,
            "events": 0,
            "panels": [],
            "kinds": decl.kinds,
            "warnings": decl.warnings
            or ["no component advertises any telemetry panel"],
        }

    interval = "1h" if hours <= 48 else "6h"
    body = {
        "size": 0,
        "query": {"bool": {"filter": [_range(hours)]}},
        "aggs": contract.build_aggs(decl.panels, interval),
    }
    res = _search(body)
    total = ((res.get("hits") or {}).get("total") or {}).get("value", 0)
    return {
        "window_hours": hours,
        "events": total,
        "panels": contract.shape(decl.panels, res.get("aggregations") or {}),
        "kinds": decl.kinds,
        "warnings": decl.warnings,
    }


@admin_router.get("/admin/telemetry/contract")
def telemetry_contract_view():
    """What each component currently advertises — the contract as the platform
    sees it. The first place to look when a panel is missing or a field will not
    group: if it is not here, no manifest declared it."""
    decl = declaration()
    fields = [
        {"name": name, **spec} for name, spec in sorted(decl.fields.items())
    ]
    return {
        "kinds": decl.kinds,
        "fields": fields,
        "panels": [
            {k: v for k, v in p.items() if k in
             ("key", "label", "tool", "type", "kind", "group_by", "hint")}
            for p in decl.panels
        ],
        "warnings": decl.warnings,
        "index_properties": decl.index_properties(),
    }


@admin_router.get("/admin/telemetry/events")
def telemetry_events(
    hours: int = Query(24, ge=1, le=24 * 90),
    kind: str | None = Query(None, description="error|request|task|llm|ui"),
    service: str | None = Query(None),
    outcome: str | None = Query(None, description="success|failure"),
    signature: str | None = Query(None, description="exact error.signature to drill into"),
    correlation_id: str | None = Query(None, description="the id returned with a 500"),
    q: str | None = Query(None, description="free text over message/error.message"),
    field: str | None = Query(None, description="advertised field to filter on"),
    value: str | None = Query(None, description="value for `field`"),
    limit: int = Query(100, ge=1, le=1000),
):
    """Raw events, newest first — the drill-down behind every summary number.

    ``correlation_id`` is the direct path from a user saying "I got an error,
    it said c3f9a1b2" to the traceback that produced it.
    """
    known = declaration().kinds
    if kind and known and kind not in known:
        raise HTTPException(
            status_code=400,
            detail=f"kind must be one of {', '.join(sorted(known))} "
                   f"(these are advertised by the deployed components)",
        )
    filters: list[dict] = [_range(hours)]
    # Generic drill-down: a panel groups by whatever it advertised, so the
    # drawer behind it has to be able to filter on that same field. Restricted
    # to advertised fields (plus the envelope) so this cannot become an
    # arbitrary query surface.
    if field and value is not None:
        allowed = set(declaration().fields) | _ENVELOPE_FIELDS
        if field not in allowed:
            raise HTTPException(
                status_code=400,
                detail=f"'{field}' is not an advertised telemetry field",
            )
        filters.append({"term": {field: value}})
    for field, value in (
        ("kind", kind),
        ("service", service),
        ("outcome", outcome),
        ("error.signature", signature),
        ("correlation_id", correlation_id),
    ):
        if value:
            filters.append({"term": {field: value}})
    if q:
        filters.append(
            {
                "multi_match": {
                    "query": q,
                    "fields": ["message", "error.message"],
                    "type": "phrase_prefix",
                }
            }
        )
    res = _search(
        {
            "size": limit,
            "query": {"bool": {"filter": filters}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
    )
    hits = ((res.get("hits") or {}).get("hits") or [])
    return {
        "count": len(hits),
        "total": ((res.get("hits") or {}).get("total") or {}).get("value", 0),
        "events": [h.get("_source") for h in hits],
    }
