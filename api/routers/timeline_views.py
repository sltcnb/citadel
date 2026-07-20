"""Saved timeline views per case — stored in Redis.

A "view" snapshots the timeline's filter state (query, artifact types, level,
flagged, time range, visible columns, sort) so an analyst can re-apply it
later without re-building the same filters by hand. Mirrors the
saved_searches router's storage shape (a JSON list under one Redis key).
"""

import json
import uuid
from datetime import datetime

import redis_keys as rk
from auth.dependencies import require_case_access
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from config import get_redis as _r

router = APIRouter(tags=["timeline-views"])


class TimelineViewIn(BaseModel):
    name: str
    query: str = ""
    selected_types: str = ""
    level: str = ""
    flagged: bool = False
    from_ts: str = ""
    to_ts: str = ""
    columns: list[str] = Field(default_factory=list)
    sort_field: str = "timestamp"
    sort_order: str = "desc"


@router.get("/cases/{case_id}/timeline-views")
def list_timeline_views(case_id: str, _case: dict = Depends(require_case_access)):
    data = _r().get(rk.case_timeline_views(case_id))
    return {"views": json.loads(data) if data else []}


@router.post("/cases/{case_id}/timeline-views")
def create_timeline_view(
    case_id: str, body: TimelineViewIn, _case: dict = Depends(require_case_access)
):
    r = _r()
    key = rk.case_timeline_views(case_id)
    views = json.loads(r.get(key) or "[]")
    new = {
        "id": str(uuid.uuid4())[:8],
        "name": body.name,
        "query": body.query,
        "selected_types": body.selected_types,
        "level": body.level,
        "flagged": body.flagged,
        "from_ts": body.from_ts,
        "to_ts": body.to_ts,
        "columns": body.columns,
        "sort_field": body.sort_field,
        "sort_order": body.sort_order,
        "created_at": datetime.utcnow().isoformat(),
    }
    views.append(new)
    r.set(key, json.dumps(views))
    return new


@router.delete("/cases/{case_id}/timeline-views/{view_id}", status_code=204)
def delete_timeline_view(
    case_id: str, view_id: str, _case: dict = Depends(require_case_access)
):
    r = _r()
    key = rk.case_timeline_views(case_id)
    views = json.loads(r.get(key) or "[]")
    r.set(key, json.dumps([v for v in views if v["id"] != view_id]))
