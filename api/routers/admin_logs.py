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

from fastapi import APIRouter, HTTPException, Query

from config import get_redis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin"])

# The services worth surfacing to an admin (others stay on stdout/cluster logs).
_TRACKED_SERVICES = ["api", "processor", "sluice", "babel", "anvil", "rosetta"]
_STREAM_PREFIX = "citadel:logs:"


def _stream_key(service: str) -> str:
    return f"{_STREAM_PREFIX}{service}"


@router.get("/admin/logs/services")
def list_log_services():
    """List services that currently have logs, with line counts."""
    r = get_redis()
    out = []
    for svc in _TRACKED_SERVICES:
        key = _stream_key(svc)
        try:
            n = r.xlen(key)
        except Exception:
            n = 0
        if n:
            out.append({"service": svc, "lines": n})
    return {"services": out, "tracked": _TRACKED_SERVICES}


@router.get("/admin/logs/{service}")
def get_service_logs(
    service: str,
    limit: int = Query(200, ge=1, le=2000),
    level: str | None = Query(None, description="filter: ERROR|WARNING|INFO|…"),
):
    """Return the most recent log lines for a service (newest first)."""
    if service not in _TRACKED_SERVICES:
        raise HTTPException(status_code=404, detail=f"unknown service '{service}'")
    r = get_redis()
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
