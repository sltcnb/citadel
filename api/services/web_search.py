"""
Public-web search for the Pilot agent.

This is the only Pilot capability that egresses off the appliance, so it is
**opt-in**: disabled by default and inert until an admin enables it and supplies
a provider API key in Settings → Pilot. Configuration lives in
``routers/pilot_settings`` (Redis ``fo:config:pilot``).

Two providers, both plain HTTPS JSON APIs (no extra deps — uses urllib):
  - tavily : POST https://api.tavily.com/search    (key in JSON body)
  - brave  : GET  https://api.search.brave.com/res/v1/web/search
             (key in the X-Subscription-Token header)

Returns a uniform shape: ``{"status": ..., "results": [{title,url,snippet}]}``.
``status`` is one of ok | disabled | unconfigured | error so the agent can tell
"turned off" from "broke".
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

_TIMEOUT = 15


def _tavily(query: str, key: str, max_results: int) -> list[dict]:
    body = json.dumps(
        {
            "api_key": key,
            "query": query,
            "max_results": max_results,
            "search_depth": "basic",
        }
    ).encode()
    req = urllib.request.Request(
        "https://api.tavily.com/search",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        data = json.loads(resp.read())
    return [
        {
            "title": r.get("title", ""),
            "url": r.get("url", ""),
            "snippet": (r.get("content", "") or "")[:500],
        }
        for r in (data.get("results") or [])
    ]


def _brave(query: str, key: str, max_results: int) -> list[dict]:
    qs = urllib.parse.urlencode({"q": query, "count": max_results})
    req = urllib.request.Request(
        f"https://api.search.brave.com/res/v1/web/search?{qs}",
        headers={"Accept": "application/json", "X-Subscription-Token": key},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        data = json.loads(resp.read())
    results = ((data.get("web") or {}).get("results")) or []
    return [
        {
            "title": r.get("title", ""),
            "url": r.get("url", ""),
            "snippet": (r.get("description", "") or "")[:500],
        }
        for r in results
    ]


_PROVIDERS = {"tavily": _tavily, "brave": _brave}


def web_search(query: str) -> dict:
    """Run a public-web search using the admin-configured provider.

    Reads live config each call so an admin toggling it takes effect at once.
    Never raises — returns a status the agent can reason about.
    """
    query = (query or "").strip()
    if not query:
        return {"status": "error", "error": "empty query", "results": []}

    try:
        from routers.pilot_settings import get_pilot_config

        cfg = get_pilot_config()
    except Exception as exc:  # config unreadable — treat as off
        return {"status": "disabled", "error": str(exc)[:120], "results": []}

    if not cfg.get("web_search_enabled"):
        return {"status": "disabled", "results": []}
    key = (cfg.get("web_search_api_key") or "").strip()
    if not key:
        return {"status": "unconfigured", "results": []}

    provider = cfg.get("web_search_provider", "tavily")
    fn = _PROVIDERS.get(provider)
    if not fn:
        return {"status": "error", "error": f"unknown provider {provider}", "results": []}

    max_results = int(cfg.get("web_search_max_results", 5) or 5)
    try:
        results = fn(query, key, max_results)
        return {"status": "ok", "provider": provider, "results": results[:max_results]}
    except urllib.error.HTTPError as exc:
        return {"status": "error", "error": f"HTTP {exc.code}", "results": []}
    except Exception as exc:
        logger.warning("web_search failed: %s", exc)
        return {"status": "error", "error": str(exc)[:160], "results": []}
