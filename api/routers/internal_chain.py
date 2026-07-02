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

    # NB: CTI IOC matching now runs as the cti_match MODULE in the worker chain
    # (persistent — indexed as cti_match timeline events), BEFORE this finalize is
    # triggered. One matching path; the AI step below sees those indexed matches.
    result["ioc_match"] = {"note": "runs as the cti_match module (persisted to timeline)"}

    # ── Auto-launch recommended modules (DECOUPLED from the LLM) ──────────────
    # Modules run automatically whenever evidence lands — the analyst does not
    # have to. This is independent of the AI step below (the LLM stays manual /
    # opt-in): gated by its own per-case flag `auto_modules` (default on).
    result["modules"] = _autolaunch_modules(case_id)

    # ── AI risk analysis — OPT-IN (the LLM never auto-runs unless the analyst
    #    armed it for this case). Modules above auto-run regardless; the LLM does
    #    not. Enabled by setting the per-case `auto_ai` flag to "1" (the Auto-AI
    #    toggle in the Ingest panel). Unset/"0" → skipped.
    if get_redis().hget(f"case:{case_id}", "auto_ai") != "1":
        result["ai_risk"] = {"skipped": "auto_ai not armed — LLM is opt-in per case"}
        logger.info("[finalize] case %s — AI risk skipped (LLM opt-in, not armed)", case_id)
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


def _autolaunch_modules(case_id: str) -> dict:
    """Launch every recommended module against its compatible files.

    Runs on ingest completion, independent of the LLM. A module is launched only
    with the case files whose extension / basename it declares as input, so each
    run gets real sources (never an empty list). Modules already run for this
    case are skipped to avoid duplicate runs on repeated finalize triggers.
    """
    from services.cases import auto_run_enabled

    if not auto_run_enabled(case_id, "auto_modules"):
        return {"skipped": "auto_modules disabled for this case"}
    try:
        from pathlib import Path

        from routers.modules import (
            CreateModuleRunRequest,
            SourceFileRef,
            _get_custom_modules,
            _get_modules,
            create_module_run,
            list_case_sources,
            list_module_runs,
            recommend_modules,
        )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"module API unavailable: {exc}"}

    try:
        sources = list_case_sources(case_id).get("sources", [])
        recommended = recommend_modules(case_id).get("recommended", [])
        already = {
            run.get("module_id") for run in list_module_runs(case_id).get("runs", [])
        }
        meta = {m["id"]: m for m in (_get_modules() + _get_custom_modules())}

        launched: list[dict] = []
        for entry in recommended:
            module_id = entry["id"]
            if module_id in already:
                continue  # don't re-run a module that already has a run
            module = meta.get(module_id) or {}
            exts = {e.lower() for e in module.get("input_extensions") or []}
            names = {n.lower() for n in module.get("input_filenames") or []}
            compatible = [
                s
                for s in sources
                if not s.get("skipped")
                and s.get("original_filename")
                and (
                    Path(s["original_filename"]).suffix.lower() in exts
                    or Path(s["original_filename"]).name.lower() in names
                )
            ]
            if not compatible:
                continue  # nothing this module can consume
            req = CreateModuleRunRequest(
                module_id=module_id,
                source_files=[
                    SourceFileRef(
                        job_id=s.get("job_id", ""),
                        filename=s.get("original_filename", ""),
                        minio_key=s.get("minio_object_key", ""),
                    )
                    for s in compatible
                ],
            )
            try:
                run = create_module_run(case_id, req)
                launched.append(
                    {"module_id": module_id, "run_id": run.get("run_id"), "files": len(compatible)}
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "[finalize] case %s — auto-launch %s failed: %s", case_id, module_id, exc
                )
        _comms.info(
            "[citadel] case %s — auto-launched %d module(s) on ingest", case_id, len(launched)
        )
        return {"launched": launched}
    except Exception as exc:  # noqa: BLE001
        logger.warning("[finalize] case %s — module auto-launch failed: %s", case_id, exc)
        return {"error": str(exc)}
