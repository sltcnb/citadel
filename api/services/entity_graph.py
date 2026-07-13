"""
Entity graph — turn the flat ECS event stream into a host ↔ user ↔ ip
(↔ process) graph so an analyst can see lateral movement at a glance.

Edges are derived from co-occurrence within events via nested ES terms aggs:

  * host → user : who logged into / acted on which host
                  (terms host.hostname.keyword » terms user.name.keyword)
  * host → ip   : which destination IPs a host talked to
                  (terms host.hostname.keyword » terms network.dst_ip)
  * user → ip   : which destination IPs a user reached
                  (terms user.name.keyword » terms network.dst_ip)

A node id is ``"{type}:{value}"`` and nodes are deduped across edge types.
A node's ``count`` is its top-level doc frequency.

The pure ``assemble_graph(agg_response)`` helper turns the ES aggregation JSON
into the ``{nodes, edges}`` structure and is unit-tested WITHOUT a live ES.
"""

from __future__ import annotations

import urllib.error
from typing import Any

from services.elasticsearch import es_request

# Size caps to keep the graph readable.
DEFAULT_LIMIT = 50  # top hosts / users
SUB_LIMIT = 20  # top sub-values (users-per-host, ips-per-entity)


def _node_id(node_type: str, value: str) -> str:
    return f"{node_type}:{value}"


def _build_query(focus: str | None) -> dict[str, Any]:
    """Scope the query to events touching ``focus`` (a hostname OR username),
    or match everything when no focus is given."""
    if not focus:
        return {"match_all": {}}
    return {
        "bool": {
            "should": [
                {"term": {"host.hostname.keyword": focus}},
                {"term": {"user.name.keyword": focus}},
            ],
            "minimum_should_match": 1,
        }
    }


def _build_aggs(limit: int, sub_limit: int) -> dict[str, Any]:
    """Two top-level terms aggs (hosts, users), each with sub-aggs for the
    entities they co-occur with. One ES round-trip yields every edge type."""
    return {
        "hosts": {
            "terms": {"field": "host.hostname.keyword", "size": limit},
            "aggs": {
                "users": {"terms": {"field": "user.name.keyword", "size": sub_limit}},
                "dst_ips": {"terms": {"field": "network.dst_ip", "size": sub_limit}},
            },
        },
        "users": {
            "terms": {"field": "user.name.keyword", "size": limit},
            "aggs": {
                "dst_ips": {"terms": {"field": "network.dst_ip", "size": sub_limit}},
            },
        },
    }


def assemble_graph(agg_response: dict[str, Any]) -> dict[str, Any]:
    """PURE helper — turn an ES aggregation response into ``{nodes, edges}``.

    ``agg_response`` is the value of the ES response ``"aggregations"`` key:

        {
          "hosts": {"buckets": [
              {"key": "WIN-01", "doc_count": 120,
               "users":   {"buckets": [{"key": "alice", "doc_count": 30}, ...]},
               "dst_ips": {"buckets": [{"key": "10.0.0.5", "doc_count": 12}, ...]}},
              ...]},
          "users": {"buckets": [
              {"key": "alice", "doc_count": 50,
               "dst_ips": {"buckets": [{"key": "10.0.0.5", "doc_count": 8}, ...]}},
              ...]},
        }

    Nodes are deduped by id across all edge types. A node's ``count`` is the
    highest top-level doc frequency seen for it (a host/user bucket count);
    IP nodes that only appear as sub-buckets take their sub-bucket count.

    Edges link the right node ids with the co-occurrence ``count``
    (the sub-bucket ``doc_count``). An empty/missing agg response → empty graph.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def _add_node(node_type: str, value: str, count: int, *, top_level: bool) -> str:
        nid = _node_id(node_type, value)
        existing = nodes.get(nid)
        if existing is None:
            nodes[nid] = {"id": nid, "type": node_type, "label": value, "count": count}
        elif top_level:
            # A top-level bucket count is authoritative; prefer the larger.
            if count > existing["count"]:
                existing["count"] = count
        return nid

    agg_response = agg_response or {}

    # --- Hosts and their neighbours (host→user, host→ip) ---
    for hb in agg_response.get("hosts", {}).get("buckets", []):
        host = hb.get("key")
        if host is None or host == "":
            continue
        host_count = int(hb.get("doc_count", 0))
        host_id = _add_node("host", host, host_count, top_level=True)

        for ub in hb.get("users", {}).get("buckets", []):
            user = ub.get("key")
            if user is None or user == "":
                continue
            ucount = int(ub.get("doc_count", 0))
            user_id = _add_node("user", user, ucount, top_level=True)
            edges.append(
                {"source": host_id, "target": user_id, "type": "host_user", "count": ucount}
            )

        for ipb in hb.get("dst_ips", {}).get("buckets", []):
            ip = ipb.get("key")
            if ip is None or ip == "":
                continue
            ipcount = int(ipb.get("doc_count", 0))
            ip_id = _add_node("ip", ip, ipcount, top_level=False)
            edges.append({"source": host_id, "target": ip_id, "type": "host_ip", "count": ipcount})

    # --- Users and their destination IPs (user→ip) ---
    for ub in agg_response.get("users", {}).get("buckets", []):
        user = ub.get("key")
        if user is None or user == "":
            continue
        ucount = int(ub.get("doc_count", 0))
        user_id = _add_node("user", user, ucount, top_level=True)

        for ipb in ub.get("dst_ips", {}).get("buckets", []):
            ip = ipb.get("key")
            if ip is None or ip == "":
                continue
            ipcount = int(ipb.get("doc_count", 0))
            ip_id = _add_node("ip", ip, ipcount, top_level=False)
            edges.append({"source": user_id, "target": ip_id, "type": "user_ip", "count": ipcount})

    # Annotate each node with its degree (number of incident edges). A high
    # degree flags a pivot: a host many users/IPs touch, or — most useful — an IP
    # that many distinct hosts talk to (a shared C2 / beacon candidate). Lets the
    # UI size/highlight hubs without a second pass.
    for n in nodes.values():
        n["degree"] = 0
    for e in edges:
        for endpoint in (e["source"], e["target"]):
            node = nodes.get(endpoint)
            if node is not None:
                node["degree"] += 1

    return {"nodes": list(nodes.values()), "edges": edges}


def build_graph(
    case_id: str,
    focus: str | None = None,
    limit: int = DEFAULT_LIMIT,
    sub_limit: int = SUB_LIMIT,
) -> dict[str, Any]:
    """Build the entity graph for a case.

    ``focus`` optionally scopes the query to events touching that host/user so
    the returned graph is that entity's neighbourhood. Returns
    ``{"nodes": [...], "edges": [...]}``; on ES error returns an empty graph.
    """
    limit = max(1, min(int(limit), 200))
    sub_limit = max(1, min(int(sub_limit), 100))

    body = {
        "size": 0,
        "query": _build_query(focus),
        "aggs": _build_aggs(limit, sub_limit),
    }
    try:
        res = es_request("POST", f"/fo-case-{case_id}-*/_search", body)
    except (urllib.error.HTTPError, Exception):
        return {"nodes": [], "edges": []}
    return assemble_graph(res.get("aggregations", {}))


def list_entities(case_id: str, limit: int = DEFAULT_LIMIT) -> dict[str, Any]:
    """List the top hosts and users in a case for a focus picker.

    Returns ``{"hosts": [{value, count}], "users": [{value, count}]}``.
    """
    limit = max(1, min(int(limit), 500))
    body = {
        "size": 0,
        "aggs": {
            "hosts": {"terms": {"field": "host.hostname.keyword", "size": limit}},
            "users": {"terms": {"field": "user.name.keyword", "size": limit}},
        },
    }
    try:
        res = es_request("POST", f"/fo-case-{case_id}-*/_search", body)
    except (urllib.error.HTTPError, Exception):
        return {"hosts": [], "users": []}
    aggs = res.get("aggregations", {})

    def _picker(name: str) -> list[dict[str, Any]]:
        out = []
        for b in aggs.get(name, {}).get("buckets", []):
            val = b.get("key")
            if val is None or val == "":
                continue
            out.append({"value": val, "count": int(b.get("doc_count", 0))})
        return out

    return {"hosts": _picker("hosts"), "users": _picker("users")}
