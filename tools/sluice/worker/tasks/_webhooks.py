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

import ipaddress
import json
import logging
import socket
import urllib.request
from urllib.parse import urlparse

import redis
import redis_keys as rk

logger = logging.getLogger(__name__)

_TIMEOUT = 10  # seconds per delivery


def _ssrf_check(url: str) -> str | None:
    """Re-validate the webhook host at delivery time.

    The API validates the URL at create/update/test, but DNS can be rebound
    afterwards — a host that resolved publicly at config time may now point at
    169.254.169.254 or an internal service. The worker cannot import from
    api/, so this ports the minimal rules of api/routers/cti.py::_validate_feed_url:
    reject non-http(s), localhost/.local/.internal, and any hostname that
    RESOLVES to a private/reserved/loopback/link-local address.

    Returns a rejection reason, or None when the URL is safe to deliver to.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return f"scheme must be http or https, got '{parsed.scheme}'"
    hostname = (parsed.hostname or "").strip().lower()
    if (
        not hostname
        or hostname == "localhost"
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
    ):
        return "host is not allowed"
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError:
        return f"host does not resolve: {hostname}"
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        ):
            return "host resolves to a private/reserved/internal address"
    return None


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
            # SSRF re-check at delivery: DNS may have been rebound since the
            # URL was validated at create/update time.
            reject = _ssrf_check(hook["url"])
            if reject:
                logger.warning(
                    "[webhooks] %s — delivery to '%s' blocked by SSRF guard: %s",
                    event,
                    hook.get("name"),
                    reject,
                )
                continue
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
