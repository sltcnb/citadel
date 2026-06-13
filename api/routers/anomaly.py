"""
Anomaly detection — rolling z-score per (host, event_id, day).

Logic:
  1. Bucket every event into (day, host, event_id).
  2. For each (host, event_id) series compute mean + stddev over the
     baseline window (default last 14 days excluding the focus day).
  3. Score each focus day's count: z = (count - mean) / stddev.
  4. Buckets with |z| >= threshold (default 3) → indexed as
     artifact_type:anomaly events.

Endpoint:
  POST /cases/{case_id}/anomaly/scan
       ?days=14&threshold=3

Idempotent — re-running overwrites the anomaly index for the case.
"""

from __future__ import annotations

import json
import logging
import math
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import UTC, datetime

from auth.dependencies import require_case_access
from fastapi import APIRouter, Depends, HTTPException, Query
from services.elasticsearch import _request as es_req

from config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["anomaly"])

ES_URL = settings.ELASTICSEARCH_URL


def _es_index(case_id: str) -> str:
    return f"fo-case-{case_id}-anomaly"


@router.get("/cases/{case_id}/anomaly")
def list_anomalies(
    case_id: str, _acl: dict = Depends(require_case_access), size: int = Query(200, le=1000)
):
    body = {
        "size": size,
        "track_total_hits": True,
        "query": {"match_all": {}},
        "sort": [{"anomaly.z_score": {"order": "desc"}}],
    }
    try:
        r = es_req("POST", f"/{_es_index(case_id)}/_search", body)
    except (urllib.error.HTTPError, Exception):
        return {"events": [], "total": 0}
    hits = r.get("hits", {}).get("hits", [])
    return {
        "events": [{"_id": h["_id"], **h["_source"]} for h in hits],
        "total": r.get("hits", {}).get("total", {}).get("value", 0),
    }


@router.post("/cases/{case_id}/anomaly/scan")
def scan_anomalies(
    case_id: str,
    case: dict = Depends(require_case_access),
    days: int = Query(14, ge=3, le=90),
    threshold: float = Query(3.0, ge=1.5, le=10.0),
):
    """Compute z-score anomalies over the last `days` of case data."""

    # Pull (day, host, event_id) histogram from ES in one composite agg
    body = {
        "size": 0,
        "aggs": {
            "by": {
                "composite": {
                    "size": 10000,
                    "sources": [
                        {
                            "day": {
                                "date_histogram": {"field": "timestamp", "calendar_interval": "1d"}
                            }
                        },
                        {
                            "host": {
                                "terms": {"field": "host.hostname.keyword", "missing_bucket": True}
                            }
                        },
                        {"eid": {"terms": {"field": "evtx.event_id", "missing_bucket": True}}},
                    ],
                }
            }
        },
    }

    series: dict[tuple, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    after = None
    rounds = 0
    while True:
        if after:
            body["aggs"]["by"]["composite"]["after"] = after
        try:
            res = es_req("POST", f"/fo-case-{case_id}-*/_search", body)
        except (urllib.error.HTTPError, Exception) as exc:
            raise HTTPException(status_code=400, detail=f"Anomaly scan failed: {exc}")
        buckets = res.get("aggregations", {}).get("by", {}).get("buckets", [])
        if not buckets:
            break
        for b in buckets:
            key = b["key"]
            day_raw = key.get("day")
            host = key.get("host")
            eid = key.get("eid")
            count = int(b["doc_count"])
            if day_raw is None or eid is None:
                continue
            # composite date_histogram returns the bucket key as epoch_ms
            # (int) when no `format` is set. Convert to YYYY-MM-DD so the
            # downstream document's `timestamp` is a parseable ISO string —
            # otherwise ES rejects the bulk insert with
            # "failed to parse date field [1780358400T00:00:00Z]".
            if isinstance(day_raw, (int, float)):
                day_str = datetime.fromtimestamp(int(day_raw) / 1000, tz=UTC).strftime("%Y-%m-%d")
            else:
                # Already an ISO string from older ES versions / formats.
                day_str = str(day_raw)[:10]
            series[(host, eid)][day_str] = count
        after = res["aggregations"]["by"].get("after_key")
        rounds += 1
        if not after or rounds >= 20:
            break

    if not series:
        # Nothing indexed yet — wipe + return
        try:
            es_req("DELETE", f"/{_es_index(case_id)}")
        except Exception:
            pass
        return {"scanned": 0, "anomalies": 0}

    # Score: for each series, treat last `days` baseline + score each day in that window
    anomalies: list[dict] = []
    for (host, eid), per_day in series.items():
        days_sorted = sorted(per_day.keys())[-days:]
        counts = [per_day[d] for d in days_sorted]
        if len(counts) < 3:
            continue
        for i, focus_day in enumerate(days_sorted):
            focus = counts[i]
            baseline = counts[:i] + counts[i + 1 :]
            if len(baseline) < 2:
                continue
            mean = sum(baseline) / len(baseline)
            var = sum((x - mean) ** 2 for x in baseline) / len(baseline)
            sd = math.sqrt(var)
            if sd == 0:
                continue
            z = (focus - mean) / sd
            if abs(z) < threshold or focus < 5:  # ignore tiny absolute spikes
                continue
            anomalies.append(
                {
                    "host": host,
                    "event_id": eid,
                    "day": focus_day,
                    "count": focus,
                    "baseline_mean": round(mean, 1),
                    "baseline_stddev": round(sd, 1),
                    "z_score": round(z, 2),
                }
            )

    # Re-index: wipe previous anomaly index + bulk-write
    try:
        es_req("DELETE", f"/{_es_index(case_id)}")
    except Exception:
        pass
    if not anomalies:
        return {"scanned": len(series), "anomalies": 0}

    lines = []
    import uuid as _u

    now_iso = datetime.now(UTC).isoformat()
    for a in anomalies:
        fo_id = _u.uuid4().hex
        doc = {
            "fo_id": fo_id,
            "case_id": case_id,
            "artifact_type": "anomaly",
            "timestamp": f"{a['day'][:10]}T00:00:00Z",
            "timestamp_desc": "Anomaly day",
            "message": (
                f"Anomalous spike: event_id={a['event_id']} host={a['host'] or '-'} "
                f"count={a['count']} (z={a['z_score']}, μ={a['baseline_mean']}, σ={a['baseline_stddev']})"
            ),
            "ingested_at": now_iso,
            "host": {"hostname": a["host"]} if a["host"] else {},
            "evtx": {"event_id": int(a["event_id"]) if str(a["event_id"]).isdigit() else None},
            "anomaly": a,
            "tags": ["anomaly"],
            "is_flagged": False,
            "is_pinned": False,
            "raw": {"summary": a},
        }
        lines.append(json.dumps({"index": {"_index": _es_index(case_id), "_id": fo_id}}))
        lines.append(json.dumps(doc))

    body_bulk = ("\n".join(lines) + "\n").encode("utf-8")
    # refresh=wait_for makes the docs visible to the next GET, otherwise the
    # 1-second refresh window leaves the panel showing "0 entries" right after
    # a successful scan.
    req = urllib.request.Request(
        f"{ES_URL.rstrip('/')}/_bulk?refresh=wait_for",
        data=body_bulk,
        headers={"Content-Type": "application/x-ndjson"},
        method="POST",
    )
    indexed = 0
    failed = 0
    first_error = None
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            bulk_res = json.loads(resp.read().decode("utf-8"))
        for item in bulk_res.get("items", []):
            op = item.get("index") or item.get("create") or {}
            if op.get("error"):
                failed += 1
                if first_error is None:
                    first_error = op["error"]
            else:
                indexed += 1
        if failed:
            logger.warning(
                "Anomaly bulk: %d/%d failed — first error: %s",
                failed,
                indexed + failed,
                first_error,
            )
    except Exception as exc:
        logger.exception("Anomaly bulk insert failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Anomaly bulk insert failed: {exc}")

    return {
        "scanned": len(series),
        "anomalies": indexed,
        "failed": failed,
        "error": str(first_error) if first_error else None,
    }
