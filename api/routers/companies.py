"""Company registry — managed list of company names for case assignment and user scoping."""

from __future__ import annotations

import json

import redis_keys as rk
from auth.dependencies import require_admin
from fastapi import APIRouter, Depends, HTTPException
from license.gate import require_feature
from pydantic import BaseModel, Field

from config import get_redis

router = APIRouter(tags=["companies"])


def _load(r) -> list[str]:
    raw = r.get(rk.COMPANIES)
    if not raw:
        return []
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []


def _save(r, companies: list[str]) -> None:
    r.set(rk.COMPANIES, json.dumps(sorted(set(companies))))


class CompanyIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)


@router.get("/companies")
def list_companies():
    """Return all registered company names. Readable by all authenticated users."""
    return {"companies": _load(get_redis())}


@router.post(
    "/companies",
    status_code=201,
    dependencies=[Depends(require_admin), Depends(require_feature("multitenancy"))],
)
def add_company(body: CompanyIn):
    """Add a company to the registry (admin only)."""
    r = get_redis()
    companies = _load(r)
    if body.name in companies:
        raise HTTPException(status_code=409, detail="Company already exists")
    companies.append(body.name)
    _save(r, companies)
    return {"companies": _load(r)}


@router.delete(
    "/companies/{name}",
    dependencies=[Depends(require_admin), Depends(require_feature("multitenancy"))],
)
def delete_company(name: str):
    """Remove a company from the registry (admin only)."""
    r = get_redis()
    companies = _load(r)
    if name not in companies:
        raise HTTPException(status_code=404, detail="Company not found")
    companies.remove(name)
    _save(r, companies)
    return {"companies": _load(r)}
