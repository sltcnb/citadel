"""Findings service — the single durable home for every analysis output.

A *finding* is written as a forensic event into ``fo-case-{case_id}-finding``.
Because that index matches the shared ``fo-case-*`` template, a finding is
immediately searchable in the timeline, picked up by the CSV / ``.citadel``
archive export, eligible for the report, and re-ingestable like any other
event — without per-feature code. This module is the one place that writes and
reads them.

The doc shape comes from ``citadel_contracts.Finding.to_event`` so the API and
any tool image agree on the schema.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from citadel_contracts import Finding

from config import settings
from services.elasticsearch import _request as es_req

logger = logging.getLogger(__name__)

ES_URL = settings.ELASTICSEARCH_URL


def findings_index(case_id: str) -> str:
    return f"fo-case-{case_id}-finding"


def index_findings(
    case_id: str, findings: list[Finding], *, replace_kind: str | None = None
) -> dict:
    """Bulk-write findings for a case.

    ``replace_kind`` — when set, every existing finding of that ``kind`` is
    deleted first, so a re-run of one feature (e.g. an anomaly scan) overwrites
    its own prior output without touching findings from other features. Dedup is
    otherwise by ``finding_id`` (stable for findings that pass a ``dedup_key``).
    """
    index = findings_index(case_id)
    if replace_kind:
        try:
            es_req(
                "POST",
                f"/{index}/_delete_by_query?refresh=true",
                {"query": {"term": {"kind": replace_kind}}},
            )
        except Exception:
            pass  # index may not exist yet — first write creates it

    if not findings:
        return {"indexed": 0, "failed": 0, "error": None}

    lines: list[str] = []
    for f in findings:
        doc = f.to_event(case_id)
        lines.append(json.dumps({"index": {"_index": index, "_id": doc["fo_id"]}}))
        lines.append(json.dumps(doc))
    body_bulk = ("\n".join(lines) + "\n").encode("utf-8")

    # refresh=wait_for so the finding is visible to the next list/search call —
    # the panel that just saved it must see it immediately.
    req = urllib.request.Request(
        f"{ES_URL.rstrip('/')}/_bulk?refresh=wait_for",
        data=body_bulk,
        headers={"Content-Type": "application/x-ndjson"},
        method="POST",
    )
    indexed = failed = 0
    first_error = None
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            bulk_res = json.loads(resp.read().decode("utf-8"))
        for item in bulk_res.get("items", []):
            op = item.get("index") or item.get("create") or {}
            if op.get("error"):
                failed += 1
                first_error = first_error or op["error"]
            else:
                indexed += 1
        if failed:
            logger.warning(
                "Findings bulk: %d/%d failed — %s", failed, indexed + failed, first_error
            )
    except Exception as exc:
        logger.exception("Findings bulk insert failed: %s", exc)
        return {"indexed": 0, "failed": len(findings), "error": str(exc)}

    return {
        "indexed": indexed,
        "failed": failed,
        "error": str(first_error) if first_error else None,
    }


def list_findings(
    case_id: str,
    *,
    kind: str | None = None,
    severity: str | None = None,
    size: int = 500,
) -> dict:
    """Return findings for a case, highest severity first."""
    filters: list[dict] = []
    if kind:
        filters.append({"term": {"kind": kind}})
    if severity:
        filters.append({"term": {"severity": severity}})
    body = {
        "size": size,
        "track_total_hits": True,
        "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
        "sort": [
            {"severity_int": {"order": "desc", "unmapped_type": "integer"}},
            {"timestamp": {"order": "desc", "unmapped_type": "date"}},
        ],
    }
    try:
        r = es_req("POST", f"/{findings_index(case_id)}/_search", body)
    except (urllib.error.HTTPError, Exception):
        return {"findings": [], "total": 0}
    hits = r.get("hits", {}).get("hits", [])
    return {
        "findings": [{"_id": h["_id"], **h["_source"]} for h in hits],
        "total": r.get("hits", {}).get("total", {}).get("value", 0),
    }


def findings_summary(case_id: str) -> dict:
    """Counts grouped by kind and by severity — for the report and dashboards."""
    body = {
        "size": 0,
        "track_total_hits": True,
        "aggs": {
            "by_kind": {"terms": {"field": "kind", "size": 50}},
            "by_severity": {"terms": {"field": "severity", "size": 10}},
        },
    }
    try:
        r = es_req("POST", f"/{findings_index(case_id)}/_search", body)
    except Exception:
        return {"total": 0, "by_kind": {}, "by_severity": {}}
    aggs = r.get("aggregations", {})
    return {
        "total": r.get("hits", {}).get("total", {}).get("value", 0),
        "by_kind": {b["key"]: b["doc_count"] for b in aggs.get("by_kind", {}).get("buckets", [])},
        "by_severity": {
            b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])
        },
    }


def delete_findings(
    case_id: str, *, finding_ids: list[str] | None = None, kind: str | None = None
) -> int:
    """Delete findings by id list or by kind. Returns deleted count (best effort)."""
    if finding_ids:
        query: dict = {"terms": {"finding_id": finding_ids}}
    elif kind:
        query = {"term": {"kind": kind}}
    else:
        query = {"match_all": {}}
    try:
        r = es_req(
            "POST", f"/{findings_index(case_id)}/_delete_by_query?refresh=true", {"query": query}
        )
        return int(r.get("deleted", 0))
    except Exception:
        return 0
