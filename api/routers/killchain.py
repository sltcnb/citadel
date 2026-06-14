"""
Reverse kill-chain assembly endpoint.

Given a confirmed-bad anchor (by fo_id, or host+timestamp), assemble the
chronological attack story for that host and tag each step with MITRE ATT&CK.
"""

from __future__ import annotations

import logging

from auth.dependencies import require_case_access
from fastapi import APIRouter, Depends, HTTPException, Query
from services.killchain import assemble_chain

logger = logging.getLogger(__name__)
router = APIRouter(tags=["killchain"])


@router.get("/cases/{case_id}/killchain")
def killchain(
    case_id: str,
    _acl: dict = Depends(require_case_access),
    fo_id: str | None = Query(default=None, description="Anchor event fo_id (confirmed-bad)"),
    host: str | None = Query(default=None, description="Anchor host (use with timestamp)"),
    timestamp: str | None = Query(default=None, description="Anchor ISO8601 timestamp"),
    window_minutes: int = Query(60, ge=1, le=1440, description="Window each side of the anchor"),
):
    """Assemble the reverse kill chain around an anchor event.

    Provide either ``fo_id`` OR ``host`` + ``timestamp``.

    Output:
      {
        "anchor": {fo_id, ts, host, user, summary, window_minutes},
        "steps":  [{ts, phase, tactic, technique, host, user, summary, fo_id}, ...],
        "tactics_covered": ["initial-access", "execution", ...]
      }
    """
    if not fo_id and not (host and timestamp):
        raise HTTPException(
            status_code=400,
            detail="Provide either fo_id, or both host and timestamp.",
        )
    try:
        result = assemble_chain(
            case_id,
            fo_id=fo_id,
            host=host,
            timestamp=timestamp,
            window_minutes=window_minutes,
        )
    except Exception as exc:
        logger.warning("killchain assembly failed: %s", exc)
        raise HTTPException(status_code=400, detail=f"Kill-chain assembly failed: {exc}")

    if result.get("error") and not result.get("steps"):
        raise HTTPException(status_code=404, detail=result["error"])
    return result
