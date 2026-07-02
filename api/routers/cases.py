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
    auto_modules: bool | None = None
    auto_ai: bool | None = None


class CaseSigmaUpdate(BaseModel):
    # True/False = explicit per-case override; null = inherit the global default.
    enabled: bool | None = None


def _redact_case(case: dict) -> dict:
    """Strip the BitLocker recovery key from API responses — it's a decryption
    secret. Callers only need to know whether one is set; the disk-image worker
    reads the raw value straight from Redis, not via the API."""
    if case is None:
        return case
    has_key = bool(case.get("bitlocker_recovery_key"))
    case.pop("bitlocker_recovery_key", None)
    case["bitlocker_key_set"] = has_key
    return case


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
        _redact_case(case)
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
    return _redact_case(case)


@router.get("/cases/{case_id}/auto-run")
def get_auto_run(case_id: str, current_user: dict = Depends(get_current_user)):
    """Which post-ingestion stages auto-run for this case (detections, IOC match, AI)."""
    case = case_svc.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _check_company_access(case, get_company_filter(current_user))
    return case_svc.get_auto_run(case_id)


@router.put("/cases/{case_id}/auto-run")
def set_auto_run(case_id: str, body: AutoRunUpdate, current_user: dict = Depends(get_current_user)):
    """Enable/disable auto-run stages per case. Disabled stages are skipped after
    each ingest (they can still be run on demand)."""
    case = case_svc.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _check_company_access(case, get_company_filter(current_user))
    return case_svc.set_auto_run(case_id, body.model_dump(exclude_none=True))


def _sigma_state(case_id: str) -> dict:
    from services import sigma_settings as ss

    return {
        "sigma_enabled": ss.sigma_enabled_for_case(case_id),
        "override": ss.get_case_sigma_override(case_id),
        "global_default": ss.get_global_sigma_enabled(),
    }


@router.get("/cases/{case_id}/sigma")
def get_case_sigma(case_id: str, current_user: dict = Depends(get_current_user)):
    """Effective Sigma state for this case: resolved value, the per-case override
    (null = inherit), and the global default it inherits from."""
    case = case_svc.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _check_company_access(case, get_company_filter(current_user))
    return _sigma_state(case_id)


@router.put("/cases/{case_id}/sigma")
def set_case_sigma(
    case_id: str, body: CaseSigmaUpdate, current_user: dict = Depends(get_current_user)
):
    """Set or clear the per-case Sigma override. enabled=null inherits the global
    default; true/false force-enable/disable Sigma rules for this case only."""
    from services import sigma_settings as ss

    case = case_svc.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _check_company_access(case, get_company_filter(current_user))
    ss.set_case_sigma_override(case_id, body.enabled)
    return _sigma_state(case_id)


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
    return _redact_case(case)


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
