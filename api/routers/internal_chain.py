"""Internal post-ingestion chain — in-cluster service calls only.

After the worker finishes detections + watchlist for a case, it calls
``POST /internal/cases/{id}/finalize`` so the API runs the steps that live on
the API side: the full CTI IOC-DB match, then (plan-permitting) the AI risk
analysis. Guarded by a shared service token — NOT user auth — so it's reachable
only from inside the cluster (api + worker are both Citadel core; this does not
touch the decoupled tool contracts).

Every step is best-effort: a slow LLM, a feature-gated plan, or a transient
error never blocks ingestion completion.
"""
from __future__ import annotations

import json
import logging
import os

from fastapi import APIRouter, Header, HTTPException

from config import get_redis

logger = logging.getLogger(__name__)
# Orchestration choreography → the dedicated "tools" log channel.
_comms = logging.getLogger("citadel.tools")
router = APIRouter(tags=["internal"])

_INTERNAL_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "")


def _require_internal(token: str | None) -> None:
    # Fail closed: if no token is configured, refuse (never run unauthenticated).
    if not _INTERNAL_TOKEN or token != _INTERNAL_TOKEN:
        raise HTTPException(status_code=403, detail="internal service token required")


@router.post("/internal/cases/{case_id}/finalize", status_code=202)
def finalize_case(case_id: str, x_internal_token: str | None = Header(default=None)):
    """Accept the post-ingestion finalize and run it OFF the request path.

    The chain (full IOC-DB match + an LLM risk call) can take a while. Running it
    inline held the worker's HTTP POST and an API thread for the whole duration —
    a couple of concurrent cases choked the pool and every page stalled. We hand
    it to a background daemon thread and return 202 immediately; the steps are
    best-effort and the worker doesn't need the result.
    """
    _require_internal(x_internal_token)
    import threading

    t = threading.Thread(target=_run_finalize_chain, args=(case_id,),
                         name=f"finalize-{case_id}", daemon=True)
    t.start()
    return {"case_id": case_id, "status": "accepted"}


def _run_finalize_chain(case_id: str) -> dict:
    """The API-side tail of the post-ingestion chain (runs in a background thread)."""
    _comms.info("[processor → citadel] case %s — post-ingestion finalize requested", case_id)
    result: dict = {"case_id": case_id, "ioc_match": None, "ai_risk": None}

    # Per-case auto-run flags — operator can disable heavy stages per case.
    from services.cases import auto_run_enabled

    # ── 1. CTI IOC-DB match ──────────────────────────────────────────────────
    if not auto_run_enabled(case_id, "auto_ioc_match"):
        result["ioc_match"] = {"skipped": "auto_ioc_match disabled for this case"}
        _comms.info("[citadel → CTI] case %s — IOC match skipped (disabled)", case_id)
    else:
        try:
            from routers.cti import match_case_iocs

            result["ioc_match"] = match_case_iocs(case_id)
            m = result["ioc_match"] or {}
            _comms.info("[citadel → CTI] case %s — IOC-DB match: %s distinct indicator(s), %s external",
                        case_id, m.get("indicator_count", 0), m.get("real_count", 0))
        except Exception as exc:  # noqa: BLE001 — never fail the chain
            logger.warning("[finalize] case %s — IOC match failed: %s", case_id, exc)
            result["ioc_match"] = {"error": str(exc)}

    # ── 2. AI risk analysis (plan-gated by the ai_assist feature) ────────────
    if not auto_run_enabled(case_id, "auto_ai"):
        result["ai_risk"] = {"skipped": "auto_ai disabled for this case"}
        logger.info("[finalize] case %s — AI risk skipped (disabled)", case_id)
        return result
    try:
        from license import get_license

        if not get_license().has_feature("ai_assist"):
            result["ai_risk"] = {"skipped": "ai_assist not enabled in license plan"}
            _comms.info("[citadel → Pilot] case %s — AI risk skipped (plan lacks ai_assist)", case_id)
        else:
            _comms.info("[citadel → Pilot] case %s — running AI risk analysis", case_id)
            from routers.llm_config import ai_analyze_case

            analysis = ai_analyze_case(case_id)
            result["ai_risk"] = analysis
            # Persist so the timeline/dashboard can show the auto-computed risk.
            try:
                get_redis().set(
                    f"fo:case_ai_risk:{case_id}",
                    json.dumps({
                        "risk_score": analysis.get("risk_score"),
                        "risk_level": analysis.get("risk_level"),
                        "executive_summary": analysis.get("executive_summary"),
                        "auto": True,
                    }),
                )
            except Exception:  # noqa: BLE001
                pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("[finalize] case %s — AI risk failed: %s", case_id, exc)
        result["ai_risk"] = {"error": str(exc)}

    logger.info("[finalize] case %s — chain complete", case_id)
    return result
