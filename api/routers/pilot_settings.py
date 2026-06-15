"""
Pilot (autonomous DFIR agent) capability settings — admin-configurable.

Mirrors the Redis-over-default config pattern in ``routers/platform_settings.py``.
The effective config is a single JSON document at ``fo:config:pilot``; admins
read/write it via ``GET/PUT /admin/pilot-config`` and the agent loop reads the
effective values through :func:`get_pilot_config`.

What it controls:
  - which agent tools are enabled (``disabled_tools``),
  - whether the Pilot may launch modules and how many per case/10 min,
  - whether the Pilot may search the public web, and with which provider/key.

Web search is the one capability that reaches OFF the appliance, so it is
**disabled by default** and only works once an admin supplies a provider key.

The api_key is a secret: GET never returns it (only ``web_search_api_key_set``),
and a blank key on PUT means "keep the stored one" (same contract as SSO).
"""

from __future__ import annotations

import json
import logging

from auth.dependencies import require_admin
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from config import get_redis as _redis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["pilot"])

_admin_dep = [Depends(require_admin)]

_PILOT_CONFIG_KEY = "fo:config:pilot"

# Every tool the agent loop can dispatch. Kept here so the UI can render a
# toggle per tool and the resolver can validate ``disabled_tools`` entries.
# `conclude` / `set_hypotheses` are control-flow, not toggleable.
KNOWN_TOOLS = (
    "search",
    "aggregate",
    "inspect",
    "time_window",
    "correlate",
    "mitre_hits",
    "entity_graph",
    "stack_rare",
    "cti_seen_before",
    "detection_rules",
    "watchlist",
    "module_runs",
    "list_modules",
    "launch_module",
    "read_module_result",
    "web_search",
)

# "model" = use the configured LLM provider's NATIVE web search (Anthropic /
# OpenAI server-side tool) — no separate key needed. tavily/brave use a
# standalone search API key.
WEB_SEARCH_PROVIDERS = ("model", "tavily", "brave")


# Hard ceiling on the per-run step budget (matches AGENT_MAX_STEPS in
# llm_config). The admin value is clamped to this.
AGENT_MAX_STEPS_CAP = 200


def _defaults() -> dict:
    return {
        "agent_max_steps": 50,
        "disabled_tools": [],
        "allow_module_launch": True,
        "module_launch_cap": 3,
        "web_search_enabled": False,
        "web_search_provider": "tavily",
        "web_search_api_key": "",
        "web_search_max_results": 5,
    }


def _stored(r) -> dict:
    raw = r.get(_PILOT_CONFIG_KEY)
    return json.loads(raw) if raw else {}


def get_pilot_config() -> dict:
    """Pure resolver other modules import for the effective values.

    Returns the Redis-over-default merge, failing open to defaults on any
    Redis/parse error so a hiccup never breaks an agent run.
    """
    base = _defaults()
    try:
        stored = _stored(_redis())
    except Exception:
        return base
    for k, v in (stored or {}).items():
        if k in base:
            base[k] = v
    return base


def web_search_enabled() -> bool:
    cfg = get_pilot_config()
    if not cfg.get("web_search_enabled"):
        return False
    # The "model" provider rides the configured LLM — no separate key needed.
    if cfg.get("web_search_provider") == "model":
        return True
    return bool(cfg.get("web_search_api_key"))


# ── Pydantic models ─────────────────────────────────────────────────────────


class PilotConfigIn(BaseModel):
    agent_max_steps: int = 50
    disabled_tools: list[str] = []
    allow_module_launch: bool = True
    module_launch_cap: int = 3
    web_search_enabled: bool = False
    web_search_provider: str = "model"
    web_search_api_key: str = ""  # blank = keep stored
    web_search_max_results: int = 5


def _redacted(cfg: dict) -> dict:
    """Public view — never echo the api key, only whether one is set."""
    out = {k: v for k, v in cfg.items() if k != "web_search_api_key"}
    out["web_search_api_key_set"] = bool(cfg.get("web_search_api_key"))
    return out


def _validate(body: PilotConfigIn, existing: dict) -> dict:
    errors: list[str] = []

    bad = [t for t in body.disabled_tools if t not in KNOWN_TOOLS]
    if bad:
        errors.append("unknown tools in disabled_tools: " + ", ".join(bad))

    if not (1 <= body.agent_max_steps <= AGENT_MAX_STEPS_CAP):
        errors.append(f"agent_max_steps must be between 1 and {AGENT_MAX_STEPS_CAP}")

    if not (1 <= body.module_launch_cap <= 50):
        errors.append("module_launch_cap must be between 1 and 50")

    if not (1 <= body.web_search_max_results <= 20):
        errors.append("web_search_max_results must be between 1 and 20")

    if body.web_search_provider not in WEB_SEARCH_PROVIDERS:
        errors.append("web_search_provider must be one of: " + ", ".join(WEB_SEARCH_PROVIDERS))

    if errors:
        raise HTTPException(status_code=422, detail="; ".join(errors))

    # Blank key on PUT keeps the previously stored one.
    key = body.web_search_api_key.strip() or existing.get("web_search_api_key", "")

    return {
        "agent_max_steps": int(body.agent_max_steps),
        "disabled_tools": sorted(set(body.disabled_tools)),
        "allow_module_launch": bool(body.allow_module_launch),
        "module_launch_cap": int(body.module_launch_cap),
        "web_search_enabled": bool(body.web_search_enabled),
        "web_search_provider": body.web_search_provider,
        "web_search_api_key": key,
        "web_search_max_results": int(body.web_search_max_results),
    }


# ── Endpoints ───────────────────────────────────────────────────────────────


@router.get("/admin/pilot-config", dependencies=_admin_dep)
def get_pilot_config_endpoint():
    """Effective Pilot configuration (secret redacted)."""
    cfg = get_pilot_config()
    out = _redacted(cfg)
    out["known_tools"] = list(KNOWN_TOOLS)
    out["web_search_providers"] = list(WEB_SEARCH_PROVIDERS)
    return out


@router.put("/admin/pilot-config", dependencies=_admin_dep)
def update_pilot_config(body: PilotConfigIn):
    """Validate and persist the Pilot configuration."""
    existing = get_pilot_config()
    cfg = _validate(body, existing)
    _redis().set(_PILOT_CONFIG_KEY, json.dumps(cfg))
    out = _redacted(get_pilot_config())
    out["known_tools"] = list(KNOWN_TOOLS)
    out["web_search_providers"] = list(WEB_SEARCH_PROVIDERS)
    return out
