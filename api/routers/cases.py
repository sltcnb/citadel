"""Case CRUD endpoints."""

from __future__ import annotations

from auth.dependencies import get_company_filter, get_current_user
from fastapi import APIRouter, Depends, HTTPException
from license.gate import check_case_limit
from pydantic import BaseModel
from services import cases as case_svc
from services.elasticsearch import bulk_case_stats, count_case_events, list_artifact_types

router = APIRouter(tags=["cases"])


class CaseCreate(BaseModel):
    name: str
    description: str = ""
    analyst: str = ""
    company: str = ""


class CaseUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    analyst: str | None = None
    status: str | None = None
    tags: list[str] | None = None
    company: str | None = None
    bitlocker_recovery_key: str | None = None


class AutoRunUpdate(BaseModel):
    auto_detections: bool | None = None
    auto_ioc_match: bool | None = None
    auto_ai: bool | None = None


def _check_company_access(case: dict, company_filter: list[str] | None) -> None:
    """Raise 403 if the user's company filter does not include this case's company."""
    if company_filter is None:
        return
    case_company = case.get("company", "")
    if case_company not in company_filter:
        raise HTTPException(
            status_code=403, detail="Access denied: case belongs to a different company"
        )


@router.get("/cases")
def list_cases(current_user: dict = Depends(get_current_user)):
    """List all cases with summary stats, filtered by user's company restrictions."""
    company_filter = get_company_filter(current_user)
    cases = case_svc.list_cases()

    # Apply company filter first, then fetch ES stats in two bulk calls
    visible = [c for c in cases if company_filter is None or c.get("company", "") in company_filter]
    stats = bulk_case_stats([c["case_id"] for c in visible])
    for case in visible:
        s = stats.get(case["case_id"], {})
        case["event_count"] = s.get("event_count", 0)
        case["artifact_types"] = s.get("artifact_types", [])
    return {"cases": visible, "total": len(visible)}


@router.post("/cases", status_code=201)
def create_case(body: CaseCreate, current_user: dict = Depends(get_current_user)):
    company_filter = get_company_filter(current_user)
    if company_filter is not None and body.company not in company_filter:
        raise HTTPException(
            status_code=403, detail="Cannot create a case for a company outside your scope"
        )
    check_case_limit()
    case = case_svc.create_case(body.name, body.description, body.analyst, body.company)
    return case


@router.get("/cases/{case_id}")
def get_case(case_id: str, current_user: dict = Depends(get_current_user)):
    """Get a single case with index summary."""
    case = case_svc.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _check_company_access(case, get_company_filter(current_user))
    case["event_count"] = count_case_events(case_id)
    case["artifact_types"] = list_artifact_types(case_id)
    return case


@router.get("/cases/{case_id}/auto-run")
def get_auto_run(case_id: str, current_user: dict = Depends(get_current_user)):
    """Which post-ingestion stages auto-run for this case (detections, IOC match, AI)."""
    if not case_svc.get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    return case_svc.get_auto_run(case_id)


@router.put("/cases/{case_id}/auto-run")
def set_auto_run(case_id: str, body: AutoRunUpdate, current_user: dict = Depends(get_current_user)):
    """Enable/disable auto-run stages per case. Disabled stages are skipped after
    each ingest (they can still be run on demand)."""
    if not case_svc.get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    return case_svc.set_auto_run(case_id, body.model_dump(exclude_none=True))


@router.put("/cases/{case_id}")
def update_case(case_id: str, body: CaseUpdate, current_user: dict = Depends(get_current_user)):
    """Update case metadata."""
    case = case_svc.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _check_company_access(case, get_company_filter(current_user))
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    case = case_svc.update_case(case_id, **updates)
    return case


@router.delete("/cases/{case_id}", status_code=204)
def delete_case(
    case_id: str, background: bool = True, current_user: dict = Depends(get_current_user)
):
    """
    Delete a case and all its data.

    By default returns immediately (204) and deletes large data in the background.
    Set ?background=false to wait for all deletions (not recommended for large cases).
    """
    case = case_svc.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _check_company_access(case, get_company_filter(current_user))
    if not case_svc.delete_case(case_id, background=background):
        raise HTTPException(status_code=404, detail="Case not found")
