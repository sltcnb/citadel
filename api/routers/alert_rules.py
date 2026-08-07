"""Alert rules per case — defined patterns checked on demand against ES."""

import json
import logging
import uuid
from datetime import UTC, datetime

import redis as redis_lib
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth.dependencies import require_case_access

logger = logging.getLogger(__name__)

import redis_keys as rk
from services import rule_eval
from services.redis_mutate import mutate_json

from config import get_redis as _r

router = APIRouter(tags=["alert-rules"])

_RUN_TTL = 7 * 86400  # keep last run for 7 days


def _load_run(r: redis_lib.Redis, case_id: str) -> dict:
    data = r.get(rk.case_alert_run(case_id))
    return (
        json.loads(data)
        if data
        else {"ran_at": None, "rules_checked": 0, "matches": [], "analyses": {}}
    )


def _save_run(r: redis_lib.Redis, case_id: str, run: dict) -> None:
    key = rk.case_alert_run(case_id)
    r.set(key, json.dumps(run))
    r.expire(key, _RUN_TTL)


def _llm_analyze_match(rule: dict, match_count: int, sample_events: list) -> dict | None:
    """Run LLM analysis for one match; silently returns None if LLM not configured or fails."""
    try:
        from routers.llm_config import _build_alert_prompt, _call_llm
        from routers.llm_config import _get_config as _llm_cfg

        cfg = _llm_cfg(_r())
        if not cfg or not cfg.get("enabled"):
            return None
        prompt = _build_alert_prompt(
            rule["name"], rule.get("query", ""), match_count, sample_events
        )
        raw = _call_llm(cfg, prompt)
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1] if "\n" in clean else clean[3:]
            clean = clean.rstrip("`").strip()
        analysis: dict = json.loads(clean)
        analysis["analyzed_at"] = datetime.now(UTC).isoformat()
        analysis["model_used"] = f"{cfg.get('provider', '?')}/{cfg.get('model', '?')}"
        return analysis
    except Exception as exc:
        logger.warning("LLM analysis failed for rule %r: %s", rule.get("name"), exc)
        return None


class AlertRuleIn(BaseModel):
    name: str
    description: str = ""
    artifact_type: str = ""
    query: str
    threshold: int = 1
    # Optional per-rule alert cooldown override (minutes); absent = default 60.
    cooldown_minutes: float | None = None


@router.get("/cases/{case_id}/alert-rules")
def list_rules(case_id: str, _acl: dict = Depends(require_case_access)):
    data = _r().get(rk.case_alert_rules(case_id))
    return {"rules": json.loads(data) if data else []}


@router.post("/cases/{case_id}/alert-rules")
def create_rule(case_id: str, body: AlertRuleIn, _acl: dict = Depends(require_case_access)):
    r = _r()
    key = rk.case_alert_rules(case_id)
    new = {
        "id": str(uuid.uuid4())[:8],
        **body.model_dump(),
        "created_at": datetime.now(UTC).isoformat(),
    }
    mutate_json(r, key, lambda rules: rules + [new], [])
    return new


@router.post("/cases/{case_id}/alert-rules/{rule_id}/run")
def run_single_rule(case_id: str, rule_id: str, _acl: dict = Depends(require_case_access)):
    """Run a single case-specific rule against this case."""
    r = _r()
    data = r.get(rk.case_alert_rules(case_id))
    rules = json.loads(data) if data else []
    rule = next((rl for rl in rules if rl["id"] == rule_id), None)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    try:
        # Shared evaluator: plain threshold or a correlation block, and the same
        # "missing index / rejected query == no match" handling this route had.
        # Cooldown dedup applies here too: an identical re-match inside the
        # window comes back suppressed_only instead of firing again.
        match = rule_eval.evaluate_with_cooldown(case_id, rule, r)
    except rule_eval.RuleEvalError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    fired = match is not None and not match.get("suppressed_only")
    return {"match": match, "rules_checked": 1, "fired": fired}


@router.delete("/cases/{case_id}/alert-rules/{rule_id}", status_code=204)
def delete_rule(case_id: str, rule_id: str, _acl: dict = Depends(require_case_access)):
    r = _r()
    key = rk.case_alert_rules(case_id)
    mutate_json(r, key, lambda rules: [rl for rl in rules if rl["id"] != rule_id], [])


# ── Last run ───────────────────────────────────────────────────────────────────


@router.get("/cases/{case_id}/alert-rules/last-run")
def get_last_run(case_id: str, _acl: dict = Depends(require_case_access)):
    """Return the most recent check run (matches + cached analyses)."""
    return _load_run(_r(), case_id)


@router.post("/cases/{case_id}/alert-rules/last-run/analyze/{rule_id}")
def analyze_run_match(case_id: str, rule_id: str, _acl: dict = Depends(require_case_access)):
    """
    (Re-)run AI analysis for a rule and persist it.
    Works even if the rule had 0 matches or no check has run yet —
    falls back to a live ES query to gather sample events.
    """
    r = _r()
    run = _load_run(r, case_id)

    match = next((m for m in run.get("matches", []) if m["rule"]["id"] == rule_id), None)

    if not match:
        # Rule not in last-run matches — look in case rules then global library
        rules_data = r.get(rk.case_alert_rules(case_id))
        rules = json.loads(rules_data) if rules_data else []
        rule = next((rl for rl in rules if rl["id"] == rule_id), None)

        if not rule:
            # Also check global library
            global_data = r.get(rk.GLOBAL_ALERT_RULES)
            global_rules = json.loads(global_data) if global_data else []
            rule = next((rl for rl in global_rules if rl["id"] == rule_id), None)

        if not rule:
            raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

        # The LLM is asked to explain the rule whether or not it fired, so an
        # unfired rule still needs a match-shaped payload.
        try:
            match = rule_eval.evaluate(case_id, rule)
        except Exception:  # noqa: BLE001 - explanation must not 500 on a bad rule
            match = None
        if match is None:
            match = {"rule": rule, "match_count": 0, "sample_events": []}

    analysis = _llm_analyze_match(match["rule"], match["match_count"], match["sample_events"])
    if analysis is None:
        raise HTTPException(status_code=400, detail="LLM not configured or analysis failed.")

    run.setdefault("analyses", {})[rule_id] = analysis
    _save_run(r, case_id, run)
    return {"analysis": analysis}


# ── Check ──────────────────────────────────────────────────────────────────────


@router.post("/cases/{case_id}/alert-rules/check")
def check_rules(case_id: str, _acl: dict = Depends(require_case_access)):
    """Run all rules against current case, persist the run, return it."""
    r = _r()
    data = r.get(rk.case_alert_rules(case_id))
    rules = json.loads(data) if data else []
    if not rules:
        run = {
            "ran_at": datetime.now(UTC).isoformat(),
            "rules_checked": 0,
            "matches": [],
            "analyses": {},
        }
        _save_run(r, case_id, run)
        return run

    matches = []
    for rule in rules:
        try:
            match = rule_eval.evaluate_with_cooldown(case_id, rule, r, sample_size=3)
            if match:
                matches.append(match)
        except Exception as exc:  # noqa: BLE001 - one bad rule must not stop the sweep
            logger.warning(
                "Alert rule %r check failed on case %s: %s", rule.get("name"), case_id, exc
            )

    run = {
        "ran_at": datetime.now(UTC).isoformat(),
        "rules_checked": len(rules),
        "matches": matches,
        # Aggregate of the per-match suppressed_count so the UI can headline
        # "3 new, 12 suppressed (cooldown)" without walking every match.
        "suppressed_total": sum(m.get("suppressed_count", 0) for m in matches),
        "analyses": {},
    }
    _save_run(r, case_id, run)
    return run
