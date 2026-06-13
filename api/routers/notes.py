"""Per-case investigator notes — stored in Redis."""

from datetime import UTC, datetime

import redis_keys as rk
from auth.dependencies import require_case_access
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from config import get_redis as _r

router = APIRouter(tags=["notes"])


class NoteIn(BaseModel):
    body: str


@router.get("/cases/{case_id}/notes")
def get_notes(case_id: str, _case: dict = Depends(require_case_access)):
    r = _r()
    data = r.hgetall(rk.case_notes(case_id))
    if not data:
        return {"body": "", "updated_at": None}
    return {
        "body": data.get("body", ""),
        "updated_at": data.get("updated_at") or None,
    }


@router.put("/cases/{case_id}/notes")
def save_notes(case_id: str, body: NoteIn, _case: dict = Depends(require_case_access)):
    now = datetime.now(UTC).isoformat()
    _r().hset(rk.case_notes(case_id), mapping={"body": body.body, "updated_at": now})
    return {"updated_at": now}
