"""Baseline diff / field-stacking (gamechanger #3).

Classic DFIR least-frequency-of-occurrence ("stacking"): on a busy case the
malicious artifact is usually the RARE one. Pick a field (process name, service,
command line, registry key…) and a target host; we surface the values present on
that host that occur on only a handful of hosts across the whole case — i.e.
"what's abnormal here" — instead of making the analyst eyeball thousands of rows.

Reuses the ECS-normalized case index + the ES service. The rarity computation is
a pure function so it's unit-testable without Elasticsearch.
"""

from __future__ import annotations

from services.elasticsearch import es_request as es_req

# Allowlisted stackable fields (keyword sub-fields) — bounds the agg surface and
# gives the UI a sensible menu. These are the artifact dimensions where "rare =
# suspicious" holds in practice.
KNOWN_STACK_FIELDS = [
    {"field": "process.name.keyword", "label": "Process names"},
    {"field": "process.command_line.keyword", "label": "Command lines"},
    {"field": "process.executable.keyword", "label": "Executable paths"},
    {"field": "process.parent.name.keyword", "label": "Parent processes"},
    {"field": "service.name.keyword", "label": "Services"},
    {"field": "registry.key.keyword", "label": "Registry keys"},
    {"field": "user.name.keyword", "label": "User accounts"},
    {"field": "network.dst_ip", "label": "Destination IPs"},
    {"field": "network.dst_domain.keyword", "label": "Destination domains"},
    {"field": "dns.question.name.keyword", "label": "DNS queries"},
    {"field": "file.path.keyword", "label": "File paths"},
]
_ALLOWED = {f["field"] for f in KNOWN_STACK_FIELDS}

_HOST_FIELD = "host.hostname.keyword"


def is_allowed_field(field: str) -> bool:
    return field in _ALLOWED


def _case_index(case_id: str) -> str:
    return f"fo-case-{case_id}-*"


def compute_rare(buckets: list[dict], max_hosts: int) -> list[dict]:
    """Pure: from terms-agg buckets, keep values present on the TARGET host that
    occur on <= max_hosts distinct hosts case-wide. Rarest (fewest hosts, then
    fewest target hits) first — the top of the list is what to look at."""
    out = []
    for b in buckets:
        host_count = (b.get("host_count") or {}).get("value", 0)
        on_target = (b.get("on_target") or {}).get("doc_count", 0)
        if on_target > 0 and host_count <= max_hosts:
            out.append({
                "value": b.get("key"),
                "target_count": on_target,
                "host_count": host_count,
                "total_count": b.get("doc_count", 0),
            })
    out.sort(key=lambda x: (x["host_count"], x["target_count"]))
    return out


def stack_field(
    case_id: str, field: str, target_host: str, max_hosts: int = 2, size: int = 1000
) -> dict:
    """Stack `field` across the case and return the values rare-yet-present on
    `target_host`. One ES terms agg with cardinality(host) + filter(target) subs."""
    body = {
        "size": 0,
        "query": {"match_all": {}},
        "aggs": {
            "vals": {
                "terms": {"field": field, "size": size},
                "aggs": {
                    "host_count": {"cardinality": {"field": _HOST_FIELD}},
                    "on_target": {"filter": {"term": {_HOST_FIELD: target_host}}},
                },
            }
        },
    }
    resp = es_req("POST", f"/{_case_index(case_id)}/_search", body)
    buckets = (resp.get("aggregations") or {}).get("vals", {}).get("buckets", [])
    return {
        "field": field,
        "target_host": target_host,
        "max_hosts": max_hosts,
        "values_examined": len(buckets),
        "rare": compute_rare(buckets, max_hosts),
    }


def list_hosts(case_id: str, size: int = 300) -> list[str]:
    """Distinct hostnames in the case (for the target-host picker)."""
    body = {"size": 0, "aggs": {"hosts": {"terms": {"field": _HOST_FIELD, "size": size}}}}
    try:
        resp = es_req("POST", f"/{_case_index(case_id)}/_search", body)
    except Exception:
        return []
    return [b["key"] for b in (resp.get("aggregations") or {}).get("hosts", {}).get("buckets", [])]
