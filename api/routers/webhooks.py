"""
Outbound webhook configuration — notify external systems when detection
rules fire.

Webhooks are stored in the fo:webhooks Redis hash (id → JSON). The
processor fires them after the auto detection-rules run completes with
matches (see processor/tasks/ingest_task.py); this router only manages
the configuration and offers a test-delivery endpoint.

Payload shape (Slack/Teams/Mattermost-compatible — they all accept a
bare {"text": ...} and ignore the extra structured fields):

    {
      "text":     "Citadel: 3 detection rule(s) fired on case Acme-DC01",
      "case_id":  "…",
      "case_name": "…",
      "matches":  [{"rule_name": "...", "match_count": 12, "level": "high"}, …],
      "ran_at":   "2026-06-04T…Z"
    }
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime

import redis_keys as rk
from auth.dependencies import require_admin
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from config import get_redis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["webhooks"])

_ALLOWED_EVENTS = {"alert_rules", "module_completed"}  # room to grow: case_created…


class WebhookIn(BaseModel):
    name: str
    url: str
    enabled: bool = True
    events: list[str] = ["alert_rules"]


def _validate(body: WebhookIn) -> None:
    if not body.name.strip():
        raise HTTPException(422, "name must not be empty")
    if not body.url.startswith(("http://", "https://")):
        raise HTTPException(422, "url must start with http:// or https://")
    _ssrf_guard(body.url)
    bad = [e for e in body.events if e not in _ALLOWED_EVENTS]
    if bad:
        raise HTTPException(422, f"unknown events: {', '.join(bad)}")


def _ssrf_guard(url: str) -> None:
    """Reject webhook URLs that resolve to internal/private/metadata addresses
    (reuses the CTI feed SSRF validator)."""
    from routers.cti import _validate_feed_url
    _validate_feed_url(url)


def _redact(hook: dict) -> dict:
    """Hide the URL's path+query in list responses — webhook URLs embed
    secrets (Slack tokens etc.). Admins re-enter the URL to change it."""
    url = hook.get("url", "")
    if "://" in url:
        scheme_host = url.split("://", 1)
        host = scheme_host[1].split("/", 1)[0]
        url = f"{scheme_host[0]}://{host}/…"
    return {**hook, "url": url}


@router.get("/admin/webhooks", dependencies=[Depends(require_admin)])
def list_webhooks():
    r = get_redis()
    hooks = []
    for raw in (r.hgetall(rk.WEBHOOKS) or {}).values():
        try:
            hooks.append(_redact(json.loads(raw)))
        except Exception:
            continue
    hooks.sort(key=lambda h: h.get("created_at", ""))
    return {"webhooks": hooks}


@router.post("/admin/webhooks", status_code=201, dependencies=[Depends(require_admin)])
def create_webhook(body: WebhookIn):
    _validate(body)
    hook = {
        "id": uuid.uuid4().hex,
        "name": body.name.strip(),
        "url": body.url.strip(),
        "enabled": body.enabled,
        "events": body.events,
        "created_at": datetime.now(UTC).isoformat(),
    }
    get_redis().hset(rk.WEBHOOKS, hook["id"], json.dumps(hook))
    return _redact(hook)


@router.put("/admin/webhooks/{hook_id}", dependencies=[Depends(require_admin)])
def update_webhook(hook_id: str, body: WebhookIn):
    _validate(body)
    r = get_redis()
    raw = r.hget(rk.WEBHOOKS, hook_id)
    if not raw:
        raise HTTPException(404, "Webhook not found")
    hook = json.loads(raw)
    hook.update(
        {
            "name": body.name.strip(),
            "url": body.url.strip(),
            "enabled": body.enabled,
            "events": body.events,
        }
    )
    r.hset(rk.WEBHOOKS, hook_id, json.dumps(hook))
    return _redact(hook)


@router.delete("/admin/webhooks/{hook_id}", dependencies=[Depends(require_admin)])
def delete_webhook(hook_id: str):
    deleted = get_redis().hdel(rk.WEBHOOKS, hook_id)
    if not deleted:
        raise HTTPException(404, "Webhook not found")
    return {"deleted": True}


@router.post("/admin/webhooks/{hook_id}/test", dependencies=[Depends(require_admin)])
def test_webhook(hook_id: str):
    """Deliver a test payload so admins can verify the URL before relying
    on it for real alerts."""
    raw = get_redis().hget(rk.WEBHOOKS, hook_id)
    if not raw:
        raise HTTPException(404, "Webhook not found")
    hook = json.loads(raw)
    _ssrf_guard(hook["url"])  # re-check at delivery (DNS may have changed since create)
    payload = {
        "text": "Citadel webhook test — configuration is working.",
        "case_id": "test",
        "case_name": "Webhook test",
        "matches": [],
        "ran_at": datetime.now(UTC).isoformat(),
    }
    req = urllib.request.Request(
        hook["url"],
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "Citadel-Webhook/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"delivered": True, "status_code": resp.status}
    except urllib.error.HTTPError as exc:
        return {"delivered": False, "status_code": exc.code, "error": str(exc)}
    except Exception as exc:
        return {"delivered": False, "error": str(exc)}
