"""Baseline diff / field-stacking endpoints (gamechanger #3)."""

from __future__ import annotations

from auth.dependencies import require_case_access
from fastapi import APIRouter, Depends, HTTPException, Query
from services import baseline as bl

router = APIRouter(tags=["baseline"])


@router.get("/cases/{case_id}/baseline/fields")
def baseline_fields(case_id: str, _acl: dict = Depends(require_case_access)):
    """Stackable fields (the UI menu) + the distinct hosts in this case."""
    return {"fields": bl.KNOWN_STACK_FIELDS, "hosts": bl.list_hosts(case_id)}


@router.get("/cases/{case_id}/baseline/stack")
def baseline_stack(
    case_id: str,
    field: str,
    host: str,
    max_hosts: int = Query(2, ge=1, le=50),
    size: int = Query(1000, ge=10, le=5000),
    _acl: dict = Depends(require_case_access),
):
    """Values present on `host` that occur on <= max_hosts hosts case-wide
    (least-frequency-of-occurrence stacking — rarest first)."""
    if not bl.is_allowed_field(field):
        raise HTTPException(status_code=400, detail=f"Field '{field}' is not stackable.")
    if not host.strip():
        raise HTTPException(status_code=400, detail="host is required")
    try:
        return bl.stack_field(case_id, field, host.strip(), max_hosts=max_hosts, size=size)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Stacking failed: {exc}")
