"""YARA rules library — CRUD and export endpoints."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime

import redis_keys as rk
from auth.dependencies import get_company_filter, get_current_user
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from redis import WatchError

from config import get_redis as _r

logger = logging.getLogger(__name__)
router = APIRouter(tags=["yara-rules"])


def _load(r, rule_id: str) -> dict | None:
    raw = r.hgetall(rk.yara_rule(rule_id))
    if not raw:
        return None
    raw["tags"] = json.loads(raw.get("tags", "[]"))
    raw["companies"] = json.loads(raw.get("companies", "[]"))
    return raw


class RuleIn(BaseModel):
    name: str
    description: str = ""
    tags: list[str] = []
    companies: list[str] = []  # [] = platform-wide; non-empty = restricted to these companies
    content: str


@router.get("/yara-rules")
def list_rules(current_user: dict = Depends(get_current_user)):
    r = _r()
    rules = [_load(r, rid) for rid in r.smembers(rk.YARA_RULES_SET)]
    rules = [ru for ru in rules if ru]
    rules.sort(key=lambda x: x.get("name", "").lower())
    company_filter = get_company_filter(current_user)
    if company_filter is not None:

        def _visible(rule: dict) -> bool:
            rule_cos = rule.get("companies") or []
            return not rule_cos or any(c in company_filter for c in rule_cos)

        rules = [ru for ru in rules if _visible(ru)]
    return {"rules": rules, "total": len(rules)}


# NOTE: /yara-rules/export must be declared before /yara-rules/{rule_id}
# so FastAPI doesn't interpret "export" as a rule_id path param.
@router.get("/yara-rules/export")
def export_rules():
    """Export all library rules as a single combined .yar file."""
    r = _r()
    parts = []
    for rid in r.smembers(rk.YARA_RULES_SET):
        raw = r.hgetall(rk.yara_rule(rid))
        if raw and raw.get("content"):
            parts.append(f"// ── {raw.get('name', rid)} ──\n{raw['content'].strip()}")
    return Response(
        content="\n\n".join(parts),
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="yara_library.yar"'},
    )


@router.get("/yara-rules/{rule_id}")
def get_rule(rule_id: str):
    rule = _load(_r(), rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="YARA rule not found")
    return rule


@router.post("/yara-rules", status_code=201)
def create_rule(body: RuleIn):
    rule_id = uuid.uuid4().hex
    now = datetime.now(UTC).isoformat()
    r = _r()
    mapping = {
        "id": rule_id,
        "name": body.name.strip(),
        "description": body.description.strip(),
        "tags": json.dumps(body.tags),
        "companies": json.dumps(body.companies),
        "content": body.content,
        "created_at": now,
        "updated_at": now,
    }
    r.hset(rk.yara_rule(rule_id), mapping=mapping)
    r.sadd(rk.YARA_RULES_SET, rule_id)
    mapping["tags"] = body.tags
    mapping["companies"] = body.companies
    return mapping


@router.put("/yara-rules/{rule_id}")
def update_rule(rule_id: str, body: RuleIn):
    r = _r()
    rule_key = rk.yara_rule(rule_id)
    now = datetime.now(UTC).isoformat()
    patch = {
        "name": body.name.strip(),
        "description": body.description.strip(),
        "tags": json.dumps(body.tags),
        "companies": json.dumps(body.companies),
        "content": body.content,
        "updated_at": now,
    }
    # Atomic check-then-act: WATCH the hash so a concurrent delete between the
    # existence check and the write can't leave a partial, set-orphaned record.
    # On the write we re-merge the existing full mapping (preserving id /
    # created_at) and re-add the id to the index set.
    for _ in range(25):
        with r.pipeline() as pipe:
            try:
                pipe.watch(rule_key)
                existing = pipe.hgetall(rule_key)
                if not existing:
                    pipe.unwatch()
                    raise HTTPException(status_code=404, detail="YARA rule not found")
                merged = {**existing, **patch}
                merged.setdefault("id", rule_id)
                merged.setdefault("created_at", now)
                pipe.multi()
                pipe.hset(rule_key, mapping=merged)
                pipe.sadd(rk.YARA_RULES_SET, rule_id)
                pipe.execute()
                break
            except WatchError:
                continue
    else:
        raise RuntimeError(f"Redis contention on {rule_key} after 25 retries")
    return _load(r, rule_id)


@router.delete("/yara-rules/{rule_id}", status_code=204)
def delete_rule(rule_id: str):
    r = _r()
    r.delete(rk.yara_rule(rule_id))
    r.srem(rk.YARA_RULES_SET, rule_id)
