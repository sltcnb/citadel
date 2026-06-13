"""Audit-trail API — read + integrity-verify the persistent, hash-chained log.

Admin-only. The write path is the middleware in ``api/main.py``; these endpoints
are read/verify only, so an operator can review chain-of-custody events and
prove the chain has not been tampered with.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Query

from services import audit

logger = logging.getLogger(__name__)
router = APIRouter(tags=["audit"])


@router.get("/audit/log")
def get_audit_log(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    actor: str | None = Query(None, description="filter by username"),
    case_id: str | None = Query(None, description="filter by case id"),
):
    """Recent audit records, newest first, paginated and optionally filtered.

    Admin-only — registered with ``require_admin`` in main.py.
    """
    items = audit.list_events(limit=limit, offset=offset, actor=actor, case_id=case_id)
    return {
        "items": items,
        "count": len(items),
        "limit": limit,
        "offset": offset,
    }


@router.get("/audit/verify")
def verify_audit_chain(
    limit: int = Query(1000, ge=1, le=50000),
):
    """Recompute the hash chain over the recent window → tamper-evidence proof.

    Returns ``{ok, broken_at, checked}``. ``ok=false`` with a ``broken_at``
    sequence means a record was altered or removed.
    """
    return audit.verify_chain(limit=limit)
