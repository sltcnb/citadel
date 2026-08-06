"""
Pilot memory / calibration / co-pilot endpoints.

Thin HTTP layer over services.pilot_memory:

  GET  /pilot/memory?kind=&value=                 recall (global; user-gated)
  POST /cases/{case_id}/pilot/memory/seen         seen_before (cross-case IOC hits)
  GET  /cases/{case_id}/pilot/watch               case_watch_status
  POST /cases/{case_id}/pilot/watch/reviewed      mark_reviewed

Global recall is gated with get_current_user (any authenticated analyst) and
filtered to the caller's company scope (+ shared records) — institutional
memory is cross-case by design, but never cross-tenant; the case-scoped routes
use require_case_access so a company-restricted analyst can't touch another
company's case. Follows the dependency conventions in routers/anomaly.py.
"""

from __future__ import annotations

from auth.dependencies import get_company_filter, get_current_user, require_case_access
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from services import pilot_memory

router = APIRouter(tags=["pilot-memory"])


class SeenBody(BaseModel):
    values: list[str] = []


def _user_memory_scope(user: dict):
    """Company scope for memory reads: None for unrestricted users (admins),
    otherwise the user's companies plus '' (shared/global records)."""
    flt = get_company_filter(user)
    if flt is None:
        return None
    return set(flt) | {""}


@router.get("/pilot/memory")
def get_memory(
    user: dict = Depends(get_current_user),
    kind: str | None = Query(None),
    value: str | None = Query(None),
):
    """Recall cross-case memory, scoped to the caller's company (+ shared
    records). When ``value`` is an IOC, also return the human-readable
    'appeared in N prior cases' summary."""
    if kind is not None and kind not in pilot_memory.KINDS:
        return {"records": [], "ioc": None, "error": f"invalid kind {kind!r}"}
    scope = _user_memory_scope(user)
    records = pilot_memory.recall(kind=kind, value=value, companies=scope)
    ioc = None
    if value and (kind in (None, "ioc")):
        ioc = pilot_memory.recall_ioc(value, companies=scope)
    return {"records": records, "ioc": ioc, "count": len(records)}


@router.post("/cases/{case_id}/pilot/memory/seen")
def post_seen(
    case_id: str,
    body: SeenBody,
    case: dict = Depends(require_case_access),
):
    """Return which of the supplied IOCs were seen in OTHER cases (cross-case
    hits only — the current case is excluded). Scoped to the case's company
    (+ shared records) so another tenant's hits never leak."""
    scope = {str(case.get("company", "") or ""), ""}
    hits = pilot_memory.seen_before(body.values, current_case=case_id, companies=scope)
    return {"case_id": case_id, "hits": hits, "count": len(hits)}


@router.get("/cases/{case_id}/pilot/watch")
def get_watch(
    case_id: str,
    _acl: dict = Depends(require_case_access),
):
    """Un-triaged-activity status for the case (watermark vs live ES count)."""
    return pilot_memory.case_watch_status(case_id)


@router.post("/cases/{case_id}/pilot/watch/reviewed")
def post_reviewed(
    case_id: str,
    _acl: dict = Depends(require_case_access),
):
    """Mark the case reviewed — set the watermark to the current event count."""
    rec = pilot_memory.mark_reviewed(case_id)
    return {"case_id": case_id, "watermark": rec}
