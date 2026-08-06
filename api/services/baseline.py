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

from services.elasticsearch import DNS_NAME_KEYWORD_FIELDS
from services.elasticsearch import es_request as es_req

# Allowlisted stackable fields (keyword sub-fields) — bounds the agg surface and
# gives the UI a sensible menu. These are the artifact dimensions where "rare =
# suspicious" holds in practice.
KNOWN_STACK_FIELDS = [
    {"field": "process.name.keyword", "label": "Process names"},
    {"field": "process.command_line.keyword", "label": "Command lines"},
    # Real fields, cross-checked against the index template, sigil's
    # field_inventory.json, and the babel parsers that emit them:
    {"field": "process.path.keyword", "label": "Executable paths"},
    {"field": "process.parent_name.keyword", "label": "Parent processes"},
    {"field": "service.name.keyword", "label": "Services"},
    {"field": "registry.key_path.keyword", "label": "Registry keys"},
    {"field": "user.name.keyword", "label": "User accounts"},
    {"field": "network.dst_ip", "label": "Destination IPs"},
    # No parser emits network.dst_domain — stack the DNS names parsers DO emit
    # (pcap dns.query_name / suricata.dns.rrname / zeek.query), merged.
    {
        "field": "dns.query_name.keyword",
        "fields": DNS_NAME_KEYWORD_FIELDS,
        "label": "DNS queries",
    },
    {"field": "file.path.keyword", "label": "File paths"},
]
_ALLOWED = {f["field"] for f in KNOWN_STACK_FIELDS}

_HOST_FIELD = "host.hostname.keyword"


def is_allowed_field(field: str) -> bool:
    return field in _ALLOWED


def _case_index(case_id: str) -> str:
    return f"fo-case-{case_id}-*"


def compute_rare(buckets: list[dict], max_hosts: int, total_hosts: int | None = None) -> list[dict]:
    """Pure: from terms-agg buckets, keep values present on the TARGET host that
    occur on <= max_hosts distinct hosts case-wide.

    Ranking (top of the list = look here first):
      1. ``unique_to_target`` — the value appears on exactly one host, and that
         host is the target. In stacking this is the strongest signal: an
         artifact that exists ONLY on the host of interest.
      2. fewest distinct hosts (rarest across the fleet)
      3. fewest target hits (a single odd occurrence beats a noisy one)

    When ``total_hosts`` is given, each result also carries a ``rarity`` score in
    [0, 1] — ``1 - host_count/total_hosts`` — so the UI can rank/scale without
    re-deriving it (1.0 ≈ present almost nowhere else, 0.0 ≈ everywhere)."""
    out = []
    for b in buckets:
        host_count = (b.get("host_count") or {}).get("value", 0)
        on_target = (b.get("on_target") or {}).get("doc_count", 0)
        if on_target > 0 and host_count <= max_hosts:
            row = {
                "value": b.get("key"),
                "target_count": on_target,
                "host_count": host_count,
                "total_count": b.get("doc_count", 0),
                "unique_to_target": host_count == 1,
            }
            if total_hosts and total_hosts > 0:
                row["rarity"] = round(1 - host_count / total_hosts, 4)
            out.append(row)
    # unique-to-target first, then rarest, then fewest target hits.
    out.sort(key=lambda x: (not x["unique_to_target"], x["host_count"], x["target_count"]))
    return out


def _stack_agg_body(field: str, target_host: str, size: int) -> dict:
    """One stacking query: terms agg on `field` with cardinality(host) +
    filter(target) sub-aggs, plus case-wide distinct-host count."""
    return {
        "size": 0,
        "query": {"match_all": {}},
        "aggs": {
            # Total distinct hosts case-wide — feeds the per-value rarity score.
            "total_hosts": {"cardinality": {"field": _HOST_FIELD}},
            "vals": {
                "terms": {"field": field, "size": size},
                "aggs": {
                    "host_count": {"cardinality": {"field": _HOST_FIELD}},
                    "on_target": {"filter": {"term": {_HOST_FIELD: target_host}}},
                },
            },
        },
    }


def _merge_stack_buckets(buckets: list[dict]) -> list[dict]:
    """Merge same-key buckets from per-field stacking aggs into one list.

    doc_count / on_target sum exactly. host_count takes the MAX across fields:
    the true cross-field union cardinality isn't derivable from per-field
    cardinalities, and max errs toward surfacing a value (analyst reviews it)
    rather than hiding a genuinely rare one."""
    merged: dict = {}
    for b in buckets:
        m = merged.setdefault(
            b["key"],
            {
                "key": b["key"],
                "doc_count": 0,
                "host_count": {"value": 0},
                "on_target": {"doc_count": 0},
            },
        )
        m["doc_count"] += b.get("doc_count", 0)
        m["host_count"]["value"] = max(
            m["host_count"]["value"], (b.get("host_count") or {}).get("value", 0)
        )
        m["on_target"]["doc_count"] += (b.get("on_target") or {}).get("doc_count", 0)
    return list(merged.values())


def stack_field(
    case_id: str, field: str, target_host: str, max_hosts: int = 2, size: int = 1000
) -> dict:
    """Stack `field` across the case and return the values rare-yet-present on
    `target_host`. Fields with several real-world spellings (e.g. DNS query
    names across pcap/suricata/zeek) declare a ``fields`` list and are stacked
    per spelling, then merged."""
    entry = next((e for e in KNOWN_STACK_FIELDS if e["field"] == field), None)
    agg_fields = (entry or {}).get("fields") or [field]

    buckets: list[dict] = []
    total_hosts = None
    for agg_field in agg_fields:
        body = _stack_agg_body(agg_field, target_host, size)
        resp = es_req("POST", f"/{_case_index(case_id)}/_search", body)
        aggs = resp.get("aggregations") or {}
        total_hosts = (aggs.get("total_hosts") or {}).get("value") or total_hosts
        buckets.extend(aggs.get("vals", {}).get("buckets", []))
    if len(agg_fields) > 1:
        buckets = _merge_stack_buckets(buckets)

    return {
        "field": field,
        "target_host": target_host,
        "max_hosts": max_hosts,
        "total_hosts": total_hosts,
        "values_examined": len(buckets),
        "rare": compute_rare(buckets, max_hosts, total_hosts),
    }


def list_hosts(case_id: str, size: int = 300) -> list[str]:
    """Distinct hostnames in the case (for the target-host picker)."""
    body = {"size": 0, "aggs": {"hosts": {"terms": {"field": _HOST_FIELD, "size": size}}}}
    try:
        resp = es_req("POST", f"/{_case_index(case_id)}/_search", body)
    except Exception:
        return []
    return [b["key"] for b in (resp.get("aggregations") or {}).get("hosts", {}).get("buckets", [])]
