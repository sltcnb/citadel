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
    KINDS,
    get_sink,
    record_ui_event,
)
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
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
    """The improvement dashboard in one query.

    Every section answers a different "what should we fix?":
    failing/slow routes (API quality), recurring errors (bugs), task outcomes
    (parser reliability), LLM spend (cost), UI errors (frontend quality).
    """
    body = {
        "size": 0,
        "query": {"bool": {"filter": [_range(hours)]}},
        "aggs": {
            "by_kind": {
                "terms": {"field": "kind", "size": 10},
                "aggs": {"outcome": {"terms": {"field": "outcome", "size": 5}}},
            },
            "by_service": {"terms": {"field": "service", "size": 20}},
            "over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h" if hours <= 48 else "6h",
                    "min_doc_count": 0,
                },
                "aggs": {"failures": {"filter": {"term": {"outcome": "failure"}}}},
            },
            "top_errors": {
                "filter": {"terms": {"kind": ["error", "ui"]}},
                "aggs": {
                    "signatures": {
                        "terms": {"field": "error.signature", "size": 20},
                        "aggs": {
                            "last_seen": {"max": {"field": "@timestamp"}},
                            "services": {"terms": {"field": "service", "size": 5}},
                            "sample": {
                                "top_hits": {
                                    "size": 1,
                                    "sort": [{"@timestamp": "desc"}],
                                    "_source": [
                                        "@timestamp", "service", "kind", "event",
                                        "message", "correlation_id",
                                        "error.type", "error.message",
                                        "http.method", "http.route", "http.path",
                                        "ui.route", "ui.component",
                                    ],
                                }
                            },
                        },
                    }
                },
            },
            "requests": {
                "filter": {"term": {"kind": "request"}},
                "aggs": {
                    "status": {"terms": {"field": "http.status_code", "size": 20}},
                    "failing_routes": {
                        "filter": {"range": {"http.status_code": {"gte": 400}}},
                        "aggs": {
                            "routes": {
                                "terms": {"field": "http.route", "size": 15},
                                "aggs": {
                                    "codes": {
                                        "terms": {"field": "http.status_code", "size": 5}
                                    }
                                },
                            }
                        },
                    },
                    "slowest_routes": {
                        "terms": {
                            "field": "http.route",
                            "size": 15,
                            "order": {"p95": "desc"},
                        },
                        "aggs": {
                            "p95": {"percentiles": {"field": "duration_ms", "percents": [95]}},
                            "avg_ms": {"avg": {"field": "duration_ms"}},
                            "max_ms": {"max": {"field": "duration_ms"}},
                        },
                    },
                },
            },
            "tasks": {
                "filter": {"term": {"kind": "task"}},
                "aggs": {
                    "by_name": {
                        "terms": {"field": "task.name", "size": 20},
                        "aggs": {
                            "outcome": {"terms": {"field": "outcome", "size": 5}},
                            "avg_ms": {"avg": {"field": "duration_ms"}},
                        },
                    },
                    "by_artifact_type": {
                        "terms": {"field": "task.artifact_type", "size": 25},
                        "aggs": {
                            "outcome": {"terms": {"field": "outcome", "size": 5}},
                            "avg_ms": {"avg": {"field": "duration_ms"}},
                            "events": {"sum": {"field": "task.events"}},
                        },
                    },
                },
            },
            "llm": {
                "filter": {"term": {"kind": "llm"}},
                "aggs": {
                    "calls": {"value_count": {"field": "llm.total_tokens"}},
                    "tokens": {"sum": {"field": "llm.total_tokens"}},
                    "cost_usd": {"sum": {"field": "llm.cost_usd"}},
                    "avg_ms": {"avg": {"field": "duration_ms"}},
                    "outcome": {"terms": {"field": "outcome", "size": 5}},
                    "by_model": {
                        "terms": {"field": "llm.model", "size": 15},
                        "aggs": {
                            "tokens": {"sum": {"field": "llm.total_tokens"}},
                            "cost_usd": {"sum": {"field": "llm.cost_usd"}},
                            "avg_ms": {"avg": {"field": "duration_ms"}},
                            "failures": {"filter": {"term": {"outcome": "failure"}}},
                        },
                    },
                    "by_purpose": {
                        "terms": {"field": "llm.purpose", "size": 15},
                        "aggs": {
                            "tokens": {"sum": {"field": "llm.total_tokens"}},
                            "avg_ms": {"avg": {"field": "duration_ms"}},
                            "failures": {"filter": {"term": {"outcome": "failure"}}},
                        },
                    },
                },
            },
            "ui": {
                "filter": {"term": {"kind": "ui"}},
                "aggs": {
                    "routes": {"terms": {"field": "ui.route", "size": 15}},
                    "components": {"terms": {"field": "ui.component", "size": 15}},
                    "sources": {"terms": {"field": "ui.source", "size": 10}},
                },
            },
        },
    }
    res = _search(body)
    aggs = res.get("aggregations") or {}
    total = ((res.get("hits") or {}).get("total") or {}).get("value", 0)

    def _pct(bucket: dict, key: str = "p95") -> float | None:
        vals = ((bucket.get(key) or {}).get("values") or {})
        return next((round(v, 1) for v in vals.values() if v is not None), None)

    return {
        "window_hours": hours,
        "events": total,
        "by_kind": [
            {
                "kind": b["key"],
                "count": b["doc_count"],
                "outcomes": {
                    o["key"]: o["doc_count"] for o in _buckets(b, "outcome")
                },
            }
            for b in _buckets(aggs, "by_kind")
        ],
        "by_service": [
            {"service": b["key"], "count": b["doc_count"]}
            for b in _buckets(aggs, "by_service")
        ],
        "over_time": [
            {
                "ts": b.get("key_as_string"),
                "count": b["doc_count"],
                "failures": (b.get("failures") or {}).get("doc_count", 0),
            }
            for b in _buckets(aggs, "over_time")
        ],
        "top_errors": [
            {
                "signature": b["key"],
                "count": b["doc_count"],
                "last_seen": (b.get("last_seen") or {}).get("value_as_string"),
                "services": [s["key"] for s in _buckets(b, "services")],
                "sample": next(
                    (
                        h.get("_source")
                        for h in (((b.get("sample") or {}).get("hits") or {}).get("hits") or [])
                    ),
                    None,
                ),
            }
            for b in _buckets(aggs, "top_errors", "signatures")
        ],
        "requests": {
            "count": (aggs.get("requests") or {}).get("doc_count", 0),
            "status": [
                {"code": b["key"], "count": b["doc_count"]}
                for b in _buckets(aggs, "requests", "status")
            ],
            "failing_routes": [
                {
                    "route": b["key"],
                    "count": b["doc_count"],
                    "codes": {str(c["key"]): c["doc_count"] for c in _buckets(b, "codes")},
                }
                for b in _buckets(aggs, "requests", "failing_routes", "routes")
            ],
            "slowest_routes": [
                {
                    "route": b["key"],
                    "count": b["doc_count"],
                    "p95_ms": _pct(b),
                    "avg_ms": round((b.get("avg_ms") or {}).get("value") or 0, 1),
                    "max_ms": round((b.get("max_ms") or {}).get("value") or 0, 1),
                }
                for b in _buckets(aggs, "requests", "slowest_routes")
            ],
        },
        "tasks": {
            "count": (aggs.get("tasks") or {}).get("doc_count", 0),
            "by_name": [
                {
                    "task": b["key"],
                    "count": b["doc_count"],
                    "outcomes": {o["key"]: o["doc_count"] for o in _buckets(b, "outcome")},
                    "avg_ms": round((b.get("avg_ms") or {}).get("value") or 0, 1),
                }
                for b in _buckets(aggs, "tasks", "by_name")
            ],
            "by_artifact_type": [
                {
                    "artifact_type": b["key"],
                    "count": b["doc_count"],
                    "outcomes": {o["key"]: o["doc_count"] for o in _buckets(b, "outcome")},
                    "avg_ms": round((b.get("avg_ms") or {}).get("value") or 0, 1),
                    "events": int((b.get("events") or {}).get("value") or 0),
                }
                for b in _buckets(aggs, "tasks", "by_artifact_type")
            ],
        },
        "llm": {
            "calls": int(((aggs.get("llm") or {}).get("calls") or {}).get("value") or 0),
            "tokens": int(((aggs.get("llm") or {}).get("tokens") or {}).get("value") or 0),
            "cost_usd": round(
                ((aggs.get("llm") or {}).get("cost_usd") or {}).get("value") or 0, 4
            ),
            "avg_ms": round(((aggs.get("llm") or {}).get("avg_ms") or {}).get("value") or 0, 1),
            "outcomes": {
                b["key"]: b["doc_count"] for b in _buckets(aggs, "llm", "outcome")
            },
            "by_model": [
                {
                    "model": b["key"],
                    "calls": b["doc_count"],
                    "tokens": int((b.get("tokens") or {}).get("value") or 0),
                    "cost_usd": round((b.get("cost_usd") or {}).get("value") or 0, 4),
                    "avg_ms": round((b.get("avg_ms") or {}).get("value") or 0, 1),
                    "failures": (b.get("failures") or {}).get("doc_count", 0),
                }
                for b in _buckets(aggs, "llm", "by_model")
            ],
            "by_purpose": [
                {
                    "purpose": b["key"],
                    "calls": b["doc_count"],
                    "tokens": int((b.get("tokens") or {}).get("value") or 0),
                    "avg_ms": round((b.get("avg_ms") or {}).get("value") or 0, 1),
                    "failures": (b.get("failures") or {}).get("doc_count", 0),
                }
                for b in _buckets(aggs, "llm", "by_purpose")
            ],
        },
        "ui": {
            "count": (aggs.get("ui") or {}).get("doc_count", 0),
            "routes": [
                {"route": b["key"], "count": b["doc_count"]}
                for b in _buckets(aggs, "ui", "routes")
            ],
            "components": [
                {"component": b["key"], "count": b["doc_count"]}
                for b in _buckets(aggs, "ui", "components")
            ],
            "sources": [
                {"source": b["key"], "count": b["doc_count"]}
                for b in _buckets(aggs, "ui", "sources")
            ],
        },
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
    limit: int = Query(100, ge=1, le=1000),
):
    """Raw events, newest first — the drill-down behind every summary number.

    ``correlation_id`` is the direct path from a user saying "I got an error,
    it said c3f9a1b2" to the traceback that produced it.
    """
    if kind and kind not in KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {', '.join(KINDS)}")
    filters: list[dict] = [_range(hours)]
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
