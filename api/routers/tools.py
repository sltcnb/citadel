"""Tool capability advertisement — the orchestrator side of the contract.

Each tool ships a ``capabilities.yaml`` describing, per platform, what it can do
and what inputs each operation needs (see citadel_contracts.capabilities). This
router aggregates every tool's declaration and serves it so the frontend can
render the UI dynamically. Change a tool's manifest → the UI changes, with no
code change here.

Sources, merged (later wins on tool-name collision):
  1. Filesystem — ``$CAPABILITIES_DIR/*.yaml`` (collected into the API image at
     build from each tool repo's capabilities.yaml), or, in dev, the repo's
     ``tools/*/capabilities.yaml``.
  2. Redis — ``fo:capabilities:<tool>`` JSON, for tools that self-register at
     runtime (truly live: re-register → UI updates with no redeploy).
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

from citadel_contracts import manifest_from_dict

logger = logging.getLogger(__name__)
router = APIRouter(tags=["tools"])

_REDIS_PREFIX = "fo:capabilities:"


def _capabilities_dirs() -> list[Path]:
    dirs: list[Path] = []
    env = os.getenv("CAPABILITIES_DIR")
    if env:
        dirs.append(Path(env))
    dirs.append(Path("/app/capabilities"))
    # Dev fallback: running from the repo, read each tool's manifest in place.
    repo_tools = Path(__file__).resolve().parents[2] / "tools"
    dirs.append(repo_tools)
    return [d for d in dirs if d.is_dir()]


def _load_yaml(path: Path) -> dict | None:
    try:
        import yaml

        doc = yaml.safe_load(path.read_text())
        return doc if isinstance(doc, dict) and doc.get("tool") else None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Bad capability manifest %s: %s", path, exc)
        return None


def _from_filesystem() -> dict[str, dict]:
    """tool_name -> raw manifest dict, from the first dir that has files."""
    found: dict[str, dict] = {}
    for d in _capabilities_dirs():
        # Flat collected dir: <tool>.yaml
        for p in sorted(d.glob("*.yaml")):
            doc = _load_yaml(p)
            if doc:
                found.setdefault(doc["tool"], doc)
        # Repo layout: <tool>/capabilities.yaml
        for p in sorted(d.glob("*/capabilities.yaml")):
            doc = _load_yaml(p)
            if doc:
                found.setdefault(doc["tool"], doc)
        if found:
            break
    return found


def _from_redis() -> dict[str, dict]:
    found: dict[str, dict] = {}
    try:
        from config import get_redis

        r = get_redis()
        for key in r.scan_iter(match=f"{_REDIS_PREFIX}*", count=200):
            raw = r.get(key)
            if not raw:
                continue
            try:
                doc = json.loads(raw)
                if isinstance(doc, dict) and doc.get("tool"):
                    found[doc["tool"]] = doc
            except (json.JSONDecodeError, ValueError):
                continue
    except Exception as exc:  # noqa: BLE001 — redis down must not break the page
        logger.debug("capability redis read skipped: %s", exc)
    return found


def _live_parsers() -> list[dict[str, str]]:
    """Live Babel parser set (built-in + custom uploads) as field options."""
    try:
        from routers.plugins import get_loader

        opts = []
        for p in get_loader().list_plugins():
            name = p.get("name", "")
            opts.append({
                "value": p.get("source_file") or name,
                "label": name,
                "desc": p.get("default_artifact_type", ""),
            })
        return opts
    except Exception as exc:  # noqa: BLE001
        logger.debug("live parser list unavailable: %s", exc)
        return []


def _live_modules() -> list[dict[str, str]]:
    """Live Anvil module set (built-in + custom registry YAML) as field options."""
    try:
        from routers.modules import _get_modules

        opts = []
        for m in _get_modules():
            name = m.get("name") or m.get("id") or ""
            opts.append({"value": name, "label": m.get("label", name),
                         "desc": m.get("description", "")})
        return opts
    except Exception as exc:  # noqa: BLE001
        logger.debug("live module list unavailable: %s", exc)
        return []


def _enrich_dynamic(d: dict[str, Any]) -> None:
    """Inject runtime-discovered units so CUSTOM parsers/modules show up without
    editing any capabilities.yaml — the dynamic half of the contract.

    - babel  → a live ``parse`` capability listing the active parser set.
    - anvil  → ``run_module`` module options filled from the live registry.
    """
    tool = d.get("tool")
    if tool == "anvil":
        modules = _live_modules()
        if modules:
            for cap in d.get("capabilities", []):
                if cap.get("key") == "run_module":
                    for f in cap.get("inputs", []):
                        if f.get("name") == "module":
                            f["options"] = modules
    elif tool == "babel":
        parsers = _live_parsers()
        if parsers:
            d.setdefault("capabilities", []).append({
                "key": "active_parsers",
                "label": "Active Parsers",
                "description": f"{len(parsers)} parser(s) currently loaded — built-in + custom (live).",
                "platforms": ["any"],
                "output": "events → timeline",
                "inputs": [{
                    "name": "parser", "type": "multiselect", "label": "Parsers",
                    "required": False, "default": [], "options": parsers,
                    "help": "Reflects the live parser set; custom uploads appear here automatically.",
                    "placeholder": "",
                }],
            })


def _aggregate() -> list[dict[str, Any]]:
    raw = _from_filesystem()
    raw.update(_from_redis())  # runtime self-registration wins over baked-in
    out: list[dict[str, Any]] = []
    for doc in raw.values():
        try:
            m = manifest_from_dict(doc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Skipping invalid manifest for %s: %s", doc.get("tool"), exc)
            continue
        d = m.to_dict()
        problems = m.validate()
        if problems:
            d["warnings"] = problems
        _enrich_dynamic(d)  # custom parsers/modules, discovered live
        out.append(d)
    out.sort(key=lambda x: x["tool"])
    return out


# Dedicated logger so tool↔Citadel chatter is easy to spot/filter in Tool Logs.
_comms = logging.getLogger("citadel.tools")


@router.get("/tools/capabilities")
def list_tool_capabilities():
    """Every tool's advertised capabilities — drives the dynamic UI."""
    manifests = _aggregate()
    _comms.info(
        "[frontend → citadel] requested all capabilities → %d tool(s): %s",
        len(manifests), ", ".join(m["tool"] for m in manifests),
    )
    return {"tools": manifests, "count": len(manifests)}


@router.get("/tools/{tool}/capabilities")
def get_tool_capabilities(tool: str):
    for m in _aggregate():
        if m["tool"] == tool:
            caps = ", ".join(c["key"] for c in m.get("capabilities", []))
            _comms.info("[frontend → citadel] requested '%s' capabilities → %s", tool, caps)
            return m
    raise HTTPException(status_code=404, detail=f"no capability manifest for '{tool}'")


@router.post("/admin/tools/sync-capabilities")
def sync_capabilities():
    """Publish the filesystem capability manifests to Redis (self-registration).

    Use after a deploy that changed a tool's capabilities.yaml — re-registers
    every manifest the API can see into ``fo:capabilities:<tool>`` so the live
    view reflects them with no rebuild. (foctl runs the equivalent at deploy,
    pushing the freshest working-tree manifests.)
    """
    from citadel_contracts import register_capability

    from config import get_redis

    r = get_redis()
    synced = []
    for doc in _from_filesystem().values():
        try:
            register_capability(r, doc)
            synced.append(doc["tool"])
            caps = ", ".join(c.get("key", "") for c in doc.get("capabilities", []))
            _comms.info(
                "[%s → citadel] announced itself: kind=%s v%s, capabilities: %s",
                doc.get("tool"), doc.get("kind", "?"), doc.get("version", "?"), caps or "(none)",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("sync failed for %s: %s", doc.get("tool"), exc)
    _comms.info("[citadel] registered %d tool manifest(s)", len(synced))
    return {"synced": sorted(synced), "count": len(synced)}
