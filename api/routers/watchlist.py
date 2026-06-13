"""IOC watchlist — persistent list of IOCs evaluated across every case.

Stored in Redis as a hash keyed by IOC id. Each entry has:
  - kind   : ip | domain | hash | cmdline | regex | custom
  - value  : the IOC literal
  - label  : human description
  - query  : Lucene clause used to match (auto-built from kind+value)
  - created_at, created_by

Evaluation: POST /watchlist/evaluate returns per-IOC hit counts across all
accessible cases. Used for dashboard widgets + 'are any of these still active?'
sweeps after a new ingestion.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime

from auth.dependencies import get_current_user, require_analyst_or_admin, require_case_access
from fastapi import APIRouter, Depends, HTTPException

from config import get_redis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["watchlist"])

_KEY = "fo:watchlist"  # Redis hash: id → JSON entry
_WL_KEY = "fo:watchlist:whitelist"  # JSON {hostnames:[], ips:[]} — company's own assets


def _get_whitelist(r) -> dict:
    raw = r.get(_WL_KEY)
    try:
        d = json.loads(raw) if raw else {}
    except (json.JSONDecodeError, TypeError):
        d = {}
    return {"hostnames": d.get("hostnames", []), "ips": d.get("ips", [])}


def _whitelist_not_clause(r) -> str:
    """A Lucene NOT clause excluding the company's own hostnames/IPs, so watchlist
    hits never fire on known-good company assets. Empty when no whitelist set."""
    wl = _get_whitelist(r)
    parts = []
    hosts = [h.strip() for h in wl.get("hostnames", []) if h.strip()]
    ips = [i.strip() for i in wl.get("ips", []) if i.strip()]
    if hosts:
        joined = " ".join(f'"{h}"' for h in hosts)
        parts.append(f"host.hostname:({joined})")
    if ips:
        joined = " ".join(f'"{i}"' for i in ips)
        parts.append(f"network.src_ip:({joined})")
        parts.append(f"network.dst_ip:({joined})")
        parts.append(f"host.ip:({joined})")
    return f"NOT ({' OR '.join(parts)})" if parts else ""


def _build_query(kind: str, value: str) -> str:
    """Translate (kind, value) into a Lucene clause."""
    v = value.strip()
    if not v:
        return ""
    if kind == "ip":
        return f'(network.src_ip:"{v}" OR network.dst_ip:"{v}" OR host.ip:"{v}")'
    if kind == "domain":
        return f'(network.dst_domain:"{v}" OR http.host:"{v}" OR browser_report.url:*{v}*)'
    if kind == "hash":
        # Match any of the three common hash fields
        return f'(process.hash_md5:"{v}" OR process.hash_sha1:"{v}" OR process.hash_sha256:"{v}")'
    if kind == "cmdline":
        return f'process.command_line:"{v}"'
    if kind == "regex":
        return f"message:/{v}/"
    return v  # custom — raw Lucene


@router.get("/watchlist")
def list_watchlist(_: dict = Depends(get_current_user)):
    """List all watchlist entries."""
    r = get_redis()
    raw = r.hgetall(_KEY) or {}
    entries = []
    for v in raw.values():
        try:
            entries.append(json.loads(v))
        except Exception:
            continue
    entries.sort(key=lambda e: e.get("created_at", ""), reverse=True)
    return {"entries": entries}


@router.post("/watchlist", dependencies=[Depends(require_analyst_or_admin)])
def add_watchlist_entry(body: dict, user: dict = Depends(get_current_user)):
    """Add an IOC to the watchlist."""
    kind = (body.get("kind") or "custom").strip().lower()
    value = (body.get("value") or "").strip()
    label = (body.get("label") or "").strip() or value
    if kind not in ("ip", "domain", "hash", "cmdline", "regex", "custom"):
        raise HTTPException(status_code=400, detail="Invalid kind")
    if not value:
        raise HTTPException(status_code=400, detail="value required")
    query = _build_query(kind, value)
    if not query:
        raise HTTPException(status_code=400, detail="Could not build query")
    entry = {
        "id": str(uuid.uuid4()),
        "kind": kind,
        "value": value,
        "label": label,
        "query": query,
        "created_at": datetime.now(UTC).isoformat(),
        "created_by": user.get("username", ""),
    }
    get_redis().hset(_KEY, entry["id"], json.dumps(entry))
    return entry


@router.delete("/watchlist/{entry_id}", dependencies=[Depends(require_analyst_or_admin)])
def delete_watchlist_entry(entry_id: str):
    deleted = get_redis().hdel(_KEY, entry_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@router.get("/cases/{case_id}/watchlist/auto-run")
def get_case_watchlist_run(case_id: str, _acl: dict = Depends(require_case_access)):
    """Return the latest auto-evaluated watchlist hits for a case (set by the
    post-ingest deferred runner). Empty if no run has happened yet."""
    raw = get_redis().get(f"fo:watchlist_runs:{case_id}")
    if not raw:
        return {"ran_at": None, "checked": 0, "hits": []}
    return json.loads(raw.decode() if isinstance(raw, bytes) else raw)


@router.get("/watchlist/whitelist")
def get_watchlist_whitelist(_: dict = Depends(get_current_user)):
    """The company's own hostnames + IPs, excluded from watchlist matching."""
    return _get_whitelist(get_redis())


@router.put("/watchlist/whitelist", dependencies=[Depends(require_analyst_or_admin)])
def set_watchlist_whitelist(body: dict, _: dict = Depends(get_current_user)):
    """Set the company asset whitelist. Body: {hostnames: [...], ips: [...]}.
    Watchlist evaluation excludes events on these assets so your own infra
    never generates watchlist noise."""
    r = get_redis()
    wl = {
        "hostnames": [str(h).strip() for h in (body.get("hostnames") or []) if str(h).strip()],
        "ips": [str(i).strip() for i in (body.get("ips") or []) if str(i).strip()],
    }
    r.set(_WL_KEY, json.dumps(wl))
    return wl


@router.post("/watchlist/evaluate", dependencies=[Depends(require_analyst_or_admin)])
def evaluate_watchlist(_: dict = Depends(get_current_user)):
    """Run every watchlist entry against every case. Returns per-IOC hit counts."""
    import urllib.error

    from services import cases as case_svc
    from services.elasticsearch import _request as es_req

    r = get_redis()
    raw = r.hgetall(_KEY) or {}
    entries = []
    for v in raw.values():
        try:
            entries.append(json.loads(v))
        except Exception:
            continue
    if not entries:
        return {"entries": []}

    cases = case_svc.list_cases()
    case_id_set = {c["case_id"] for c in cases}
    by_id = {c["case_id"]: c for c in cases}
    not_clause = _whitelist_not_clause(r)  # exclude company's own assets

    results = []
    for e in entries:
        q = f'({e["query"]}) AND {not_clause}' if not_clause else e["query"]
        agg = {
            "size": 0,
            "track_total_hits": True,
            "query": {
                "query_string": {
                    "query": q,
                    "default_operator": "AND",
                    "fields": ["*"],
                    "allow_leading_wildcard": True,
                    "analyze_wildcard": True,
                }
            },
            "aggs": {"by_case": {"terms": {"field": "case_id", "size": 1000}}},
        }
        try:
            res = es_req("POST", "/fo-case-*/_search", agg)
        except (urllib.error.HTTPError, Exception) as exc:
            logger.warning("Watchlist eval failed for %s: %s", e.get("label"), exc)
            results.append({**e, "total_hits": 0, "matched_cases": [], "error": str(exc)})
            continue
        buckets = (res.get("aggregations", {}).get("by_case", {}) or {}).get("buckets", [])
        matched = [
            {
                "case_id": b["key"],
                "case_name": by_id.get(b["key"], {}).get("name", b["key"]),
                "hits": b["doc_count"],
            }
            for b in buckets
            if b["key"] in case_id_set
        ]
        total = sum(m["hits"] for m in matched)
        results.append({**e, "total_hits": total, "matched_cases": matched})

    results.sort(key=lambda e: e.get("total_hits", 0), reverse=True)
    return {"entries": results}
