"""Admin log viewer — recent structured logs of the tools that matter.

Tools (the processor/Sluice/Babel/Anvil worker, the API, …) ship JSON log lines
to capped Redis streams ``citadel:logs:<service>`` via
``observability.RedisLogHandler``. These admin-only endpoints expose them so an
operator can tail what each tool is doing without shelling into pods.

Anvil per-run analyzer logs already live at ``fo:module_log:<run_id>`` and are
surfaced via the existing modules API; this viewer covers the per-service streams.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Path, Query

from config import get_redis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin"])

# Preferred ordering hint — but the list is discovered dynamically from the
# live log streams, so ANY tool (built-in, custom, or a swapped-in replacement)
# that ships logs appears here automatically. "tools" carries the tool↔Citadel
# orchestration trace (announcements, capability requests, finalize chain).
_TRACKED_SERVICES = ["tools", "api", "processor", "sluice", "babel", "anvil", "rosetta"]
_STREAM_PREFIX = "citadel:logs:"


def _stream_key(service: str) -> str:
    return f"{_STREAM_PREFIX}{service}"


def _discover_services(r) -> list[str]:
    """Every service that currently has a log stream — dynamic, so new/swapped
    tools surface without a code change. Known services keep their order first."""
    found: list[str] = []
    try:
        for key in r.scan_iter(match=f"{_STREAM_PREFIX}*", count=200):
            svc = (key.decode() if isinstance(key, bytes) else key)[len(_STREAM_PREFIX):]
            if svc:
                found.append(svc)
    except Exception:
        pass
    ordered = [s for s in _TRACKED_SERVICES if s in found]
    ordered += sorted(s for s in found if s not in _TRACKED_SERVICES)
    return ordered


@router.get("/admin/logs/services")
def list_log_services():
    """List services that currently have logs, with line counts (discovered live)."""
    r = get_redis()
    services = _discover_services(r)
    out = []
    for svc in services:
        try:
            n = r.xlen(_stream_key(svc))
        except Exception:
            n = 0
        if n:
            out.append({"service": svc, "lines": n})
    return {"services": out, "tracked": services}


@router.get("/admin/logs/{service}")
def get_service_logs(
    service: str,
    limit: int = Query(200, ge=1, le=2000),
    level: str | None = Query(None, description="filter: ERROR|WARNING|INFO|…"),
):
    """Return the most recent log lines for a service (newest first)."""
    r = get_redis()
    # Accept any service that has (or had) a stream — list is dynamic.
    if service != "all" and service not in _discover_services(r):
        raise HTTPException(status_code=404, detail=f"unknown service '{service}'")
    try:
        # newest-first; fetch a little extra when filtering by level
        fetch = limit * 4 if level else limit
        entries = r.xrevrange(_stream_key(service), count=fetch)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"log store unavailable: {exc}")

    want = level.upper() if level else None
    lines = []
    for _id, fields in entries:
        lvl = fields.get("level", "")
        if want and lvl != want:
            continue
        lines.append(
            {
                "ts": fields.get("ts", ""),
                "level": lvl,
                "logger": fields.get("logger", ""),
                # Prefer the discrete message; fall back to the legacy full line.
                "msg": fields.get("msg", fields.get("line", "")),
                "exc": fields.get("exc") or None,
            }
        )
        if len(lines) >= limit:
            break
    return {"service": service, "count": len(lines), "lines": lines}


@router.delete("/admin/logs/{service}")
def clear_service_logs(service: str = Path(...)):
    """Reset (delete) the captured log stream for one service, or all of them
    when ``service`` is ``all``. Only clears the admin viewer's Redis streams —
    stdout/cluster logs are untouched."""
    r = get_redis()
    discovered = _discover_services(r)
    targets = discovered if service == "all" else [service]
    if service != "all" and service not in discovered:
        raise HTTPException(status_code=404, detail=f"unknown service '{service}'")
    cleared = 0
    for svc in targets:
        try:
            cleared += r.delete(_stream_key(svc))
        except Exception:
            pass
    return {"cleared": cleared, "services": targets}
