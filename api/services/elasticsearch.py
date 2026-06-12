"""Elasticsearch service — index management and querying."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from config import settings

logger = logging.getLogger(__name__)

ES_URL = settings.ELASTICSEARCH_URL

INDEX_TEMPLATE = {
    "index_patterns": ["fo-case-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "5s",
            "index.mapping.total_fields.limit": 2000,
            "codec": "best_compression",
        },
        "mappings": {
            "dynamic": "true",
            "properties": {
                "fo_id": {"type": "keyword"},
                "case_id": {"type": "keyword"},
                "artifact_type": {"type": "keyword"},
                "source_file": {"type": "keyword", "index": False},
                "ingest_job_id": {"type": "keyword"},
                "ingested_at": {"type": "date"},
                "timestamp": {"type": "date"},
                "timestamp_desc": {"type": "keyword"},
                "message": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 512}},
                },
                "tags": {"type": "keyword"},
                "analyst_note": {"type": "text"},
                "is_flagged": {"type": "boolean"},
                "host": {"type": "object", "dynamic": True},
                "user": {"type": "object", "dynamic": True},
                "process": {"type": "object", "dynamic": True},
                "network": {"type": "object", "dynamic": True},
                "http": {"type": "object", "dynamic": True},
                "error": {"type": "object", "dynamic": True},
                "access_log": {"type": "object", "dynamic": True},
                "mitre": {"type": "object", "dynamic": True},
                "evtx": {"type": "object", "dynamic": True},
                "prefetch": {"type": "object", "dynamic": True},
                "mft": {"type": "object", "dynamic": True},
                "registry": {"type": "object", "dynamic": True},
                "lnk": {"type": "object", "dynamic": True},
                "login_event": {"type": "object", "dynamic": True},
                "antivirus": {"type": "object", "dynamic": True},
                "plaso": {"type": "object", "dynamic": True},
                "raw": {"type": "object", "enabled": False},
            },
        },
    },
    "priority": 100,
    "composed_of": [],
}


def _request(method: str, path: str, body: dict | None = None) -> dict:
    url = f"{ES_URL}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def apply_index_template() -> None:
    """Apply the shared index template for all fo-case-* indices."""
    try:
        _request("PUT", "/_index_template/fo-cases-template", INDEX_TEMPLATE)
        logger.info("Applied fo-cases-template")
    except Exception as exc:
        logger.warning("Could not apply index template: %s", exc)


def list_case_indices(case_id: str) -> list[str]:
    """Return all Elasticsearch indices for a given case."""
    try:
        result = _request("GET", f"/_cat/indices/fo-case-{case_id}-*?format=json")
        return [idx["index"] for idx in result]
    except Exception:
        return []


def list_artifact_types(case_id: str) -> list[str]:
    """Return distinct artifact types present in the case."""
    indices = list_case_indices(case_id)
    prefix = f"fo-case-{case_id}-"
    return [idx[len(prefix) :] for idx in indices if idx.startswith(prefix)]


def count_case_events(case_id: str) -> int:
    """Return total event count across all case indices."""
    try:
        result = _request("GET", f"/fo-case-{case_id}-*/_count")
        return result.get("count", 0)
    except Exception:
        return 0


def bulk_case_stats(case_ids: list[str]) -> dict[str, dict]:
    """
    Return event_count and artifact_types for multiple cases in two ES calls
    instead of 2N. Used by the case list endpoint to avoid per-case queries.
    """
    if not case_ids:
        return {}

    id_set = set(case_ids)
    result: dict[str, dict] = {cid: {"event_count": 0, "artifact_types": []} for cid in case_ids}

    # One _cat/indices call for artifact types across all cases
    try:
        indices = _request("GET", "/_cat/indices/fo-case-*?format=json&h=index")
        for entry in indices:
            name = entry.get("index", "")
            # index format: fo-case-{case_id}-{artifact_type}
            if not name.startswith("fo-case-"):
                continue
            rest = name[len("fo-case-") :]
            dash = rest.find("-")
            if dash == -1:
                continue
            cid, atype = rest[:dash], rest[dash + 1 :]
            if cid in id_set:
                result[cid]["artifact_types"].append(atype)
    except Exception:
        pass

    # One _msearch call for event counts (header + body pairs in ndjson)
    try:
        lines = []
        for cid in case_ids:
            lines.append(json.dumps({"index": f"fo-case-{cid}-*"}))
            lines.append(
                json.dumps({"query": {"match_all": {}}, "size": 0, "track_total_hits": True})
            )
        ndjson = "\n".join(lines) + "\n"
        url = f"{ES_URL}/_msearch"
        req = urllib.request.Request(
            url,
            data=ndjson.encode(),
            headers={"Content-Type": "application/x-ndjson"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            msearch = json.loads(resp.read())
        for cid, response in zip(case_ids, msearch.get("responses", [])):
            result[cid]["event_count"] = response.get("hits", {}).get("total", {}).get("value", 0)
    except Exception:
        pass

    return result


_SEARCH_FIELDS = [
    "message",
    "host.hostname",
    "user.name",
    "process.name",
    "process.cmdline",
    "process.args",
    "network.src_ip",
    "network.dst_ip",
    "network.protocol",
    "network.action",
    "http.request_path",
    "http.user_agent",
]


# Detect Lucene operators / structure; if any present, treat the input as a
# crafted query and don't apply the smart-wildcard fallback.
_LUCENE_OPERATORS_RE = __import__("re").compile(
    r"""(?:                       # any of:
        :|                        # field qualifier
        \bAND\b|\bOR\b|\bNOT\b|   # boolean ops
        [()\[\]{}"\\]|            # grouping / quoting / escape
        /[^/]+/|                  # /regex/
        [*?]|                     # wildcards
        \^[0-9]                   # boost
    )""",
    __import__("re").VERBOSE,
)


def _looks_like_bare_ioc(q: str) -> bool:
    """True if q has no Lucene operators — treat as a bare IOC-style token."""
    q = (q or "").strip()
    if not q:
        return False
    if _LUCENE_OPERATORS_RE.search(q):
        return False
    # Don't double-wildcard a short word; only meaningful for IOC-like strings
    # containing punctuation (dots/dashes/slashes/colons).
    return any(c in q for c in ".-/_")


def search_events(
    case_id: str,
    query: str = "",
    artifact_type: str | None = None,
    from_ts: str | None = None,
    to_ts: str | None = None,
    extra_filters: list[dict] | None = None,
    page: int = 0,
    size: int = 100,
    sort_field: str = "timestamp",
    sort_order: str = "asc",
    regexp: bool = False,  # kept for API compat, ignored — use /regex/ in query instead
    search_after: list | None = None,
) -> dict[str, Any]:
    """
    Search events in a case with full-text query and field filters.
    Returns ES hits response dict.
    """
    index = f"fo-case-{case_id}-{artifact_type}" if artifact_type else f"fo-case-{case_id}-*"

    must_clauses: list[dict] = []
    filter_clauses: list[dict] = []

    if query:
        # Full Lucene query_string over all indexed fields.
        # Inline regexes work natively: /pattern/ syntax in the query string.
        #
        # Smart-bare-term: if the input is a single token with NO Lucene operators
        # (e.g. "pan.bar", "192.168.1.1", "evil.exe"), augment the search with
        # a wildcard variant so substring/IOC-style searches match across
        # tokenized URL/path fields where analyzer splits on punctuation.
        clauses = [
            {
                "query_string": {
                    "query": query,
                    "default_operator": "AND",
                    "fields": ["*"],
                    "allow_leading_wildcard": True,
                    "analyze_wildcard": True,
                }
            }
        ]
        if _looks_like_bare_ioc(query):
            wq = f"*{query.strip()}*"
            clauses.append(
                {
                    "query_string": {
                        "query": wq,
                        "fields": ["*"],
                        "allow_leading_wildcard": True,
                        "analyze_wildcard": True,
                    }
                }
            )
        if len(clauses) == 1:
            must_clauses.extend(clauses)
        else:
            must_clauses.append({"bool": {"should": clauses, "minimum_should_match": 1}})

    if from_ts or to_ts:
        range_filter: dict = {"range": {"timestamp": {}}}
        if from_ts:
            range_filter["range"]["timestamp"]["gte"] = from_ts
        if to_ts:
            range_filter["range"]["timestamp"]["lte"] = to_ts
        filter_clauses.append(range_filter)

    if extra_filters:
        filter_clauses.extend(extra_filters)

    es_query: dict[str, Any] = {
        "bool": {
            "must": must_clauses or [{"match_all": {}}],
            "filter": filter_clauses,
        }
    }

    body = {
        "query": es_query,
        "size": size,
        "sort": [
            {sort_field: {"order": sort_order, "unmapped_type": "keyword", "missing": "_last"}},
            {"_doc": {"order": "asc"}},
        ],
        "_source": {"excludes": ["raw.xml"]},
        "track_total_hits": 10000,  # exact up to 10k, then "10000+"; avoids full count cost
    }
    # search_after = cursor pagination (deep, O(1)) — required past the 10k
    # max_result_window. Falls back to shallow `from` only for the first pages.
    if search_after:
        body["search_after"] = search_after
    else:
        body["from"] = min(page * size, 9500)

    try:
        result = _request("POST", f"/{index}/_search", body)
        return result
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 404):
            return {"hits": {"total": {"value": 0}, "hits": []}}
        raise


def _iso_to_epoch_ms(ts: str | None) -> int | None:
    """Parse an ISO8601 timestamp (Z or offset) to epoch milliseconds, or None."""
    if not ts:
        return None
    from datetime import datetime

    try:
        s = ts.replace("Z", "+00:00")
        return int(datetime.fromisoformat(s).timestamp() * 1000)
    except (ValueError, TypeError):
        return None


def get_search_facets(
    case_id: str,
    query: str = "",
    artifact_type: str | None = None,
    from_ts: str | None = None,
    to_ts: str | None = None,
) -> dict[str, Any]:
    """Return aggregation buckets for the facet panel.

    Activity histogram:
      • No range → ``auto_date_histogram`` over the whole case (ES picks interval).
      • Range set (zoomed) → a fixed-interval ``date_histogram`` whose interval is
        (to-from)/N and whose ``extended_bounds`` span the EXACT selected window,
        so the bars fill the selection edge-to-edge (including empty buckets)
        instead of only where data happens to land.
    """
    index = f"fo-case-{case_id}-{artifact_type}" if artifact_type else f"fo-case-{case_id}-*"

    must = (
        [{"query_string": {"query": query, "fields": _SEARCH_FIELDS}}]
        if query
        else [{"match_all": {}}]
    )
    from_ms = _iso_to_epoch_ms(from_ts)
    to_ms = _iso_to_epoch_ms(to_ts)
    if from_ts or to_ts:
        rng = {}
        if from_ts:
            rng["gte"] = from_ts
        if to_ts:
            rng["lt"] = to_ts
        must.append({"range": {"timestamp": rng}})

    _TARGET_BUCKETS = 80
    if from_ms is not None and to_ms is not None and to_ms > from_ms:
        interval_ms = max(1, (to_ms - from_ms) // _TARGET_BUCKETS)
        events_over_time = {
            "date_histogram": {
                "field": "timestamp",
                "fixed_interval": f"{interval_ms}ms",
                "min_doc_count": 0,  # keep empty buckets so the window is full
                "extended_bounds": {"min": from_ms, "max": to_ms - 1},
            }
        }
    else:
        events_over_time = {"auto_date_histogram": {"field": "timestamp", "buckets": _TARGET_BUCKETS}}

    body = {
        "query": {"bool": {"must": must}},
        "size": 0,
        "aggs": {
            "by_artifact_type": {"terms": {"field": "artifact_type", "size": 20}},
            "by_hostname": {"terms": {"field": "host.hostname.keyword", "size": 20}},
            "by_username": {"terms": {"field": "user.name.keyword", "size": 20}},
            "by_event_id": {"terms": {"field": "evtx.event_id", "size": 30}},
            "by_channel": {"terms": {"field": "evtx.channel.keyword", "size": 20}},
            # Network / web facets — empty (and hidden) for evtx-only cases, but
            # make the filter panel useful for access-log / network data.
            "by_src_ip": {"terms": {"field": "network.src_ip", "size": 20}},
            "by_dest_ip": {"terms": {"field": "network.dst_ip", "size": 20}},
            "by_status_code": {"terms": {"field": "http.status_code", "size": 20}},
            "by_http_method": {"terms": {"field": "http.method.keyword", "size": 10}},
            "by_domain": {"terms": {"field": "dns.question.name.keyword", "size": 20}},
            "events_over_time": events_over_time,
        },
    }

    try:
        result = _request("POST", f"/{index}/_search", body)
        return result.get("aggregations", {})
    except Exception:
        return {}


def get_event_by_id(case_id: str, fo_id: str) -> dict | None:
    """Fetch a single event by its fo_id."""
    body = {
        "query": {"term": {"fo_id": fo_id}},
        "size": 1,
    }
    try:
        result = _request("POST", f"/fo-case-{case_id}-*/_search", body)
        hits = result.get("hits", {}).get("hits", [])
        if hits:
            return {"_id": hits[0]["_id"], "_index": hits[0]["_index"], **hits[0]["_source"]}
        return None
    except Exception:
        return None


def update_event(case_id: str, index: str, doc_id: str, partial: dict) -> bool:
    """Partially update an event document."""
    try:
        _request("POST", f"/{index}/_update/{doc_id}", {"doc": partial})
        return True
    except Exception:
        return False


_ARTIFACTS_INDEX = "fo-artifacts"

_ARTIFACTS_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "case_id": {"type": "keyword"},
            "job_id": {"type": "keyword"},
            "filename": {"type": "keyword"},
            "plugin_used": {"type": "keyword"},
            "mime_type": {"type": "keyword"},
            "events_indexed": {"type": "integer"},
            "skipped": {"type": "boolean"},
            "minio_key": {"type": "keyword", "index": False},
            "completed_at": {"type": "date"},
        }
    },
}


def ensure_artifacts_index() -> None:
    try:
        _request("GET", f"/{_ARTIFACTS_INDEX}")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            try:
                _request("PUT", f"/{_ARTIFACTS_INDEX}", _ARTIFACTS_MAPPING)
                logger.info("Created %s index", _ARTIFACTS_INDEX)
            except Exception as create_exc:
                logger.warning("Could not create artifacts index: %s", create_exc)


def index_artifact(doc: dict) -> None:
    job_id = doc.get("job_id", "unknown")
    try:
        _request("PUT", f"/{_ARTIFACTS_INDEX}/_doc/{job_id}", doc)
    except Exception as exc:
        logger.warning("Failed to index artifact %s: %s", job_id, exc)


def list_case_artifacts(case_id: str, size: int = 5000) -> list[dict]:
    body = {
        "query": {"term": {"case_id": case_id}},
        "size": size,
        "sort": [{"completed_at": {"order": "desc"}}],
    }
    try:
        result = _request("POST", f"/{_ARTIFACTS_INDEX}/_search", body)
        return [h["_source"] for h in result.get("hits", {}).get("hits", [])]
    except Exception:
        return []


def search_events_for_rule(case_id: str, query: str, size: int = 10) -> list[dict]:
    """Run a Lucene query against a case and return the first N hits (for Studio rule playground)."""
    index = f"fo-case-{case_id}-*"
    body = {
        "query": {
            "query_string": {
                "query": query,
                "default_operator": "AND",
                "fields": ["*"],
                "allow_leading_wildcard": True,
                "analyze_wildcard": True,
            }
        },
        "size": size,
        "sort": [{"timestamp": {"order": "asc"}}],
        "_source": {"excludes": ["raw.xml"]},
    }
    try:
        result = _request("POST", f"/{index}/_search", body)
        return [h["_source"] for h in result.get("hits", {}).get("hits", [])]
    except Exception:
        return []


def delete_case_indices(case_id: str) -> None:
    """Delete all indices for a case."""
    indices = list_case_indices(case_id)
    if not indices:
        logger.info("No indices found for case %s", case_id)
        return
    index_list = ",".join(indices)
    try:
        _request("DELETE", f"/{index_list}")
        logger.info("Deleted %d indices for case %s", len(indices), case_id)
    except Exception as exc:
        logger.warning("Error deleting case %s indices: %s", case_id, exc)
