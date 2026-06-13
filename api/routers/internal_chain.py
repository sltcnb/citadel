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
from datetime import UTC, datetime

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

    # NB: CTI IOC matching now runs as the cti_match MODULE in the worker chain
    # (persistent — indexed as cti_match timeline events), BEFORE this finalize is
    # triggered. One matching path; the AI step below sees those indexed matches.
    result["ioc_match"] = {"note": "runs as the cti_match module (persisted to timeline)"}

    # ── AI risk analysis (plan-gated by the ai_assist feature) ───────────────
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
            # Index the AI risk as a timeline event (artifact_type: ai_risk) so it
            # appears in the timeline like everything else. Deterministic _id →
            # the latest analysis upserts instead of stacking duplicates.
            try:
                from services.elasticsearch import _request as _esr
                lvl = (analysis.get("risk_level") or "info").lower()
                _esr("POST", f"/fo-case-{case_id}-ai_risk/_doc/ai_risk-{case_id}?refresh=true", {
                    "fo_id": f"ai_risk-{case_id}",
                    "case_id": case_id,
                    "artifact_type": "ai_risk",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "timestamp_desc": "AI Risk Analysis",
                    "message": f"AI risk {analysis.get('risk_score', '?')}/100 "
                               f"({analysis.get('risk_level', 'unknown')}) — "
                               f"{(analysis.get('executive_summary') or '')[:200]}",
                    "ai_risk": {
                        "level": lvl,
                        "risk_score": analysis.get("risk_score"),
                        "risk_level": analysis.get("risk_level"),
                        "rule_title": "AI Risk Analysis",
                        "executive_summary": analysis.get("executive_summary", ""),
                    },
                    "tags": [], "is_flagged": False,
                })
            except Exception as exc:  # noqa: BLE001
                logger.warning("[finalize] case %s — AI risk indexing failed: %s", case_id, exc)
            # Persist so the dashboard can show the auto-computed risk.
            try:
                get_redis().set(
                    f"fo:case_ai_risk:{case_id}",
                    json.dumps({
                        "risk_score": analysis.get("risk_score"),
                        "risk_level": analysis.get("risk_level"),
                        "executive_summary": analysis.get("executive_summary"),
                        "auto": True,
                    }),
                    ex=7 * 86400,  # TTL so stale per-case AI risk doesn't leak indefinitely
                )
            except Exception:  # noqa: BLE001
                pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("[finalize] case %s — AI risk failed: %s", case_id, exc)
        result["ai_risk"] = {"error": str(exc)}

    logger.info("[finalize] case %s — chain complete", case_id)
    return result
