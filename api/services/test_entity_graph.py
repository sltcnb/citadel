"""
Unit tests for the PURE ``assemble_graph`` helper — no live Elasticsearch.

Run: ``pytest api/services/test_entity_graph.py`` (pytest not installed in this
env; tests are correct-by-construction and also runnable as a plain script).
"""

from __future__ import annotations

from services.entity_graph import assemble_graph


def _realistic_aggs() -> dict:
    """A realistic ES aggregations response: two hosts, shared user + shared IP."""
    return {
        "hosts": {
            "buckets": [
                {
                    "key": "WIN-01",
                    "doc_count": 120,
                    "users": {
                        "buckets": [
                            {"key": "alice", "doc_count": 30},
                            {"key": "bob", "doc_count": 10},
                        ]
                    },
                    "dst_ips": {
                        "buckets": [
                            {"key": "10.0.0.5", "doc_count": 12},
                        ]
                    },
                },
                {
                    "key": "WIN-02",
                    "doc_count": 80,
                    "users": {
                        "buckets": [
                            # 'alice' also acts on WIN-02 → lateral movement.
                            {"key": "alice", "doc_count": 15},
                        ]
                    },
                    "dst_ips": {
                        "buckets": [
                            {"key": "10.0.0.5", "doc_count": 7},
                        ]
                    },
                },
            ]
        },
        "users": {
            "buckets": [
                {
                    "key": "alice",
                    "doc_count": 200,  # top-level user count is authoritative
                    "dst_ips": {
                        "buckets": [
                            {"key": "10.0.0.5", "doc_count": 8},
                        ]
                    },
                },
            ]
        },
    }


def test_nodes_deduped_with_correct_types_and_ids():
    g = assemble_graph(_realistic_aggs())
    nodes = {n["id"]: n for n in g["nodes"]}

    # 'alice' appears under both hosts AND as a top-level user bucket → ONE node.
    assert "user:alice" in nodes
    assert sum(1 for n in g["nodes"] if n["id"] == "user:alice") == 1

    # '10.0.0.5' appears under two hosts and one user → ONE node.
    assert sum(1 for n in g["nodes"] if n["id"] == "ip:10.0.0.5") == 1

    # Expected, fully-deduped node set.
    assert set(nodes) == {
        "host:WIN-01",
        "host:WIN-02",
        "user:alice",
        "user:bob",
        "ip:10.0.0.5",
    }

    # Types and id scheme "{type}:{value}".
    assert nodes["host:WIN-01"]["type"] == "host"
    assert nodes["host:WIN-01"]["label"] == "WIN-01"
    assert nodes["user:alice"]["type"] == "user"
    assert nodes["ip:10.0.0.5"]["type"] == "ip"

    # The authoritative top-level user count (200) wins over per-host sub counts.
    assert nodes["user:alice"]["count"] == 200
    assert nodes["host:WIN-01"]["count"] == 120


def test_edges_link_right_ids_with_counts():
    g = assemble_graph(_realistic_aggs())
    edges = {(e["source"], e["target"], e["type"]): e["count"] for e in g["edges"]}

    # host→user edges with the sub-bucket co-occurrence count.
    assert edges[("host:WIN-01", "user:alice", "host_user")] == 30
    assert edges[("host:WIN-01", "user:bob", "host_user")] == 10
    assert edges[("host:WIN-02", "user:alice", "host_user")] == 15

    # host→ip edges.
    assert edges[("host:WIN-01", "ip:10.0.0.5", "host_ip")] == 12
    assert edges[("host:WIN-02", "ip:10.0.0.5", "host_ip")] == 7

    # user→ip edge.
    assert edges[("user:alice", "ip:10.0.0.5", "user_ip")] == 8

    # Exactly the six edges above — no extras, no dupes.
    assert len(g["edges"]) == 6


def test_node_degree_flags_pivots():
    g = assemble_graph(_realistic_aggs())
    deg = {n["id"]: n["degree"] for n in g["nodes"]}
    # The shared IP is touched by 2 hosts + 1 user → degree 3 (beacon candidate).
    assert deg["ip:10.0.0.5"] == 3
    # alice: host_user(WIN-01), host_user(WIN-02), user_ip → degree 3 (pivot user).
    assert deg["user:alice"] == 3
    # bob only touches WIN-01 → degree 1.
    assert deg["user:bob"] == 1
    # degree equals total edge endpoints.
    assert sum(deg.values()) == 2 * len(g["edges"])


def test_empty_response_yields_empty_graph():
    assert assemble_graph({}) == {"nodes": [], "edges": []}
    assert assemble_graph(None) == {"nodes": [], "edges": []}
    # Present-but-empty bucket lists also yield an empty graph.
    assert assemble_graph({"hosts": {"buckets": []}, "users": {"buckets": []}}) == {
        "nodes": [],
        "edges": [],
    }


def test_missing_and_blank_keys_skipped():
    aggs = {
        "hosts": {
            "buckets": [
                {
                    "key": "",  # blank host — skipped entirely
                    "doc_count": 5,
                    "users": {"buckets": [{"key": "x", "doc_count": 1}]},
                },
                {
                    "key": "H1",
                    "doc_count": 9,
                    "users": {"buckets": [{"key": "", "doc_count": 3}]},  # blank user skipped
                    "dst_ips": {"buckets": []},
                },
            ]
        },
    }
    g = assemble_graph(aggs)
    assert {n["id"] for n in g["nodes"]} == {"host:H1"}
    assert g["edges"] == []


if __name__ == "__main__":
    test_nodes_deduped_with_correct_types_and_ids()
    test_edges_link_right_ids_with_counts()
    test_node_degree_flags_pivots()
    test_empty_response_yields_empty_graph()
    test_missing_and_blank_keys_skipped()
    print("all entity_graph tests passed")
