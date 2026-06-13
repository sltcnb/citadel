"""Saved search bookmarks per case — stored in Redis."""

import json
import uuid
from datetime import datetime

import redis_keys as rk
from auth.dependencies import require_case_access
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from config import get_redis as _r

router = APIRouter(tags=["saved-searches"])


class SavedSearchIn(BaseModel):
    name: str
    query: str = ""
    filters: dict = {}


@router.get("/cases/{case_id}/saved-searches")
def list_saved_searches(case_id: str, _case: dict = Depends(require_case_access)):
    data = _r().get(rk.case_saved_searches(case_id))
    return {"searches": json.loads(data) if data else []}


@router.post("/cases/{case_id}/saved-searches")
def create_saved_search(
    case_id: str, body: SavedSearchIn, _case: dict = Depends(require_case_access)
):
    r = _r()
    key = rk.case_saved_searches(case_id)
    searches = json.loads(r.get(key) or "[]")
    new = {
        "id": str(uuid.uuid4())[:8],
        "name": body.name,
        "query": body.query,
        "filters": body.filters,
        "created_at": datetime.utcnow().isoformat(),
    }
    searches.append(new)
    r.set(key, json.dumps(searches))
    return new


@router.delete("/cases/{case_id}/saved-searches/{search_id}", status_code=204)
def delete_saved_search(
    case_id: str, search_id: str, _case: dict = Depends(require_case_access)
):
    r = _r()
    key = rk.case_saved_searches(case_id)
    searches = json.loads(r.get(key) or "[]")
    r.set(key, json.dumps([s for s in searches if s["id"] != search_id]))
