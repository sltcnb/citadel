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
            # kind/severity are dynamically mapped text fields; the exact-value
            # .keyword subfield is what a terms agg can group on (plain "kind"
            # 400s with "Fielddata is disabled" and the summary silently read 0).
            "by_kind": {"terms": {"field": "kind.keyword", "size": 50}},
            "by_severity": {"terms": {"field": "severity.keyword", "size": 10}},
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


# Triage review states. Findings written before triage existed carry no
# ``triage_status`` field at all — everywhere below treats "field missing" as
# "open" so the review queue is backwards compatible.
TRIAGE_STATUSES = ("open", "reviewed", "false_positive")


def _open_status_filter() -> dict:
    """Matches docs whose triage status is open — explicitly OR by absence."""
    return {
        "bool": {
            "should": [
                {"term": {"triage_status.keyword": "open"}},
                {"bool": {"must_not": {"exists": {"field": "triage_status"}}}},
            ],
            "minimum_should_match": 1,
        }
    }


def set_triage_status(case_id: str, finding_ids: list[str], status: str) -> int:
    """Bulk-set the triage status on finding docs. Returns updated count.

    Uses ``update_by_query`` (one round-trip for any id list) with the same
    ``terms`` on ``finding_id`` matching that :func:`delete_findings` uses, and
    ``refresh=true`` so the queue reflects the change on the next list call —
    mirroring how ``update_event`` writes flags back onto event docs.
    """
    if status not in TRIAGE_STATUSES:
        raise ValueError(f"invalid triage status: {status}")
    if not finding_ids:
        return 0
    body = {
        "query": {"terms": {"finding_id": finding_ids}},
        "script": {
            "source": "ctx._source.triage_status = params.status",
            "lang": "painless",
            "params": {"status": status},
        },
    }
    try:
        r = es_req(
            "POST",
            f"/{findings_index(case_id)}/_update_by_query?refresh=true&conflicts=proceed",
            body,
        )
        return int(r.get("updated", 0))
    except Exception:
        logger.exception("Findings triage update failed")
        return 0


def triage_list(
    case_id: str,
    *,
    status: str | None = None,
    severity: str | None = None,
    kind: str | None = None,
    source: str | None = None,
    size: int = 500,
) -> dict:
    """Filtered triage listing + review-queue counts.

    The hit list honours every filter (status/severity/kind/source); the counts
    are faceted the standard way — computed over the severity/kind/source
    filters but NOT the status filter, so every status bucket stays visible
    while one is selected. ``missing: open`` on the status terms agg folds
    pre-triage findings into the open bucket.
    """
    filters: list[dict] = []
    # kind/severity/source_feature are dynamically mapped text fields — exact
    # matching goes through the .keyword subfield (same reason as the summary).
    if severity:
        filters.append({"term": {"severity.keyword": severity}})
    if kind:
        filters.append({"term": {"kind.keyword": kind}})
    if source:
        filters.append({"term": {"source_feature.keyword": source}})

    query_filters = list(filters)
    if status:
        query_filters.append(
            _open_status_filter()
            if status == "open"
            else {"term": {"triage_status.keyword": status}}
        )

    body = {
        "size": size,
        "track_total_hits": True,
        "query": {"bool": {"filter": query_filters}} if query_filters else {"match_all": {}},
        "sort": [
            {"severity_int": {"order": "desc", "unmapped_type": "integer"}},
            {"timestamp": {"order": "desc", "unmapped_type": "date"}},
        ],
        "aggs": {
            # Scope the queue counts to the non-status filters only.
            "queue": {
                "filter": {"bool": {"filter": filters}} if filters else {"match_all": {}},
                "aggs": {
                    "by_status": {
                        "terms": {
                            "field": "triage_status.keyword",
                            "missing": "open",
                            "size": 10,
                        },
                        "aggs": {
                            "by_severity": {
                                "terms": {"field": "severity.keyword", "size": 10}
                            }
                        },
                    },
                    "by_kind": {"terms": {"field": "kind.keyword", "size": 50}},
                    "by_source": {"terms": {"field": "source_feature.keyword", "size": 50}},
                },
            },
        },
    }
    empty = {
        "findings": [],
        "total": 0,
        "size": size,
        "counts": {
            "by_status": {s: 0 for s in TRIAGE_STATUSES},
            "by_status_severity": {s: {} for s in TRIAGE_STATUSES},
            "by_kind": {},
            "by_source": {},
        },
    }
    try:
        r = es_req("POST", f"/{findings_index(case_id)}/_search", body)
    except Exception:
        return empty
    hits = r.get("hits", {}).get("hits", [])
    queue = r.get("aggregations", {}).get("queue", {})
    by_status: dict[str, int] = {}
    by_status_severity: dict[str, dict[str, int]] = {}
    for b in queue.get("by_status", {}).get("buckets", []):
        by_status[b["key"]] = b["doc_count"]
        by_status_severity[b["key"]] = {
            sb["key"]: sb["doc_count"]
            for sb in b.get("by_severity", {}).get("buckets", [])
        }
    for s in TRIAGE_STATUSES:
        by_status.setdefault(s, 0)
        by_status_severity.setdefault(s, {})
    return {
        "findings": [{"_id": h["_id"], **h["_source"]} for h in hits],
        "total": r.get("hits", {}).get("total", {}).get("value", 0),
        "size": size,
        "counts": {
            "by_status": by_status,
            "by_status_severity": by_status_severity,
            "by_kind": {
                b["key"]: b["doc_count"]
                for b in queue.get("by_kind", {}).get("buckets", [])
            },
            "by_source": {
                b["key"]: b["doc_count"]
                for b in queue.get("by_source", {}).get("buckets", [])
            },
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
