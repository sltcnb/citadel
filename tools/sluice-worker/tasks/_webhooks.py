"""
Outbound webhook delivery for processor tasks.

Webhooks are configured via the API (api/routers/webhooks.py) and stored
in the fo:webhooks Redis hash. Tasks call fire_webhooks() with an event
name and a payload; delivery is best-effort — a dead endpoint must never
fail the task that triggered it.

Payloads always carry a Slack/Teams/Mattermost-compatible "text" field
plus structured data for SOAR consumers.
"""

from __future__ import annotations

import json
import logging
import urllib.request

import redis
import redis_keys as rk

logger = logging.getLogger(__name__)

_TIMEOUT = 10  # seconds per delivery


def fire_webhooks(r: redis.Redis, event: str, payload: dict) -> None:
    """POST *payload* to every enabled webhook subscribed to *event*."""
    hooks = []
    try:
        for raw in (r.hgetall(rk.WEBHOOKS) or {}).values():
            try:
                h = json.loads(raw)
            except Exception:
                continue
            if h.get("enabled") and event in (h.get("events") or []):
                hooks.append(h)
    except Exception as exc:
        logger.warning("[webhooks] could not load webhooks: %s", exc)
        return
    if not hooks:
        return

    body = json.dumps(payload).encode()
    for hook in hooks:
        try:
            req = urllib.request.Request(
                hook["url"],
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "Citadel-Webhook/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                logger.info(
                    "[webhooks] %s — delivered to '%s' (%d)", event, hook.get("name"), resp.status
                )
        except Exception as exc:
            logger.warning(
                "[webhooks] %s — delivery to '%s' failed: %s", event, hook.get("name"), exc
            )
