"""Unit tests for the tamper-evident audit chain in services/audit.py.

Mirrors conftest.py's fakeredis pattern: a FakeRedis(decode_responses=True)
patched into ``audit.get_redis``, and ``es_request`` monkeypatched to a no-op so
the tests need no Elasticsearch. We assert that records chain (each hash depends
on the previous), that seq increments, and that ``verify_chain`` returns ok for
an intact chain and ok=False with the correct ``broken_at`` after tampering.
"""

import sys
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services import audit  # noqa: E402


@pytest.fixture
def audit_redis(monkeypatch):
    """FakeRedis wired into the audit module + ES indexing stubbed to a no-op."""
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(audit, "get_redis", lambda: fake, raising=True)
    # Neutralise ES so durability indexing is exercised but needs no cluster.
    import services.elasticsearch as es

    monkeypatch.setattr(es, "es_request", lambda *a, **k: {}, raising=True)
    return fake


def _emit(n):
    """Append n events and return the resulting records."""
    return [
        audit.record_event(
            actor=f"user{i}", role="analyst", method="POST",
            path=f"/api/v1/cases/c{i}", case_id=f"c{i}", status=200, ip="10.0.0.1",
        )
        for i in range(n)
    ]


def test_seq_increments_monotonically(audit_redis):
    recs = _emit(5)
    assert [r["seq"] for r in recs] == [1, 2, 3, 4, 5]


def test_each_hash_depends_on_prev(audit_redis):
    recs = _emit(3)
    # First record chains off the genesis hash.
    assert recs[0]["prev_hash"] == audit.GENESIS_HASH
    # Each subsequent prev_hash is the previous record's hash.
    assert recs[1]["prev_hash"] == recs[0]["hash"]
    assert recs[2]["prev_hash"] == recs[1]["hash"]
    # Hash is exactly sha256(prev_hash + canonical_json(record_without_hash)).
    without_hash = {k: v for k, v in recs[1].items() if k != "hash"}
    assert recs[1]["hash"] == audit.compute_hash(recs[1]["prev_hash"], without_hash)


def test_hash_is_sensitive_to_payload(audit_redis):
    recs = _emit(1)
    without_hash = {k: v for k, v in recs[0].items() if k != "hash"}
    tampered = {**without_hash, "actor": "attacker"}
    assert audit.compute_hash(recs[0]["prev_hash"], tampered) != recs[0]["hash"]


def test_verify_chain_ok_for_intact_chain(audit_redis):
    _emit(10)
    result = audit.verify_chain(limit=100)
    assert result == {"ok": True, "broken_at": None, "checked": 10}


def test_verify_chain_detects_tamper(audit_redis):
    _emit(10)
    # Tamper with record at index 4 (seq 5) directly in the Redis store: change
    # a field WITHOUT recomputing its hash → its stored hash no longer matches.
    import json

    raw = audit_redis.lrange(audit._LIST_KEY, 0, -1)
    rec = json.loads(raw[4])
    assert rec["seq"] == 5
    rec["status"] = 403  # forge the recorded outcome
    audit_redis.lset(audit._LIST_KEY, 4, json.dumps(rec, separators=(",", ":")))

    result = audit.verify_chain(limit=100)
    assert result["ok"] is False
    assert result["broken_at"] == 5
    assert result["checked"] == 5  # stops at the first broken link


def test_verify_chain_detects_deletion(audit_redis):
    """Removing a record breaks the prev_hash continuity of its successor."""
    _emit(6)
    raw = audit_redis.lrange(audit._LIST_KEY, 0, -1)
    # Drop record at index 2 (seq 3); rewrite the list without it.
    audit_redis.delete(audit._LIST_KEY)
    kept = [r for i, r in enumerate(raw) if i != 2]
    for item in kept:
        audit_redis.rpush(audit._LIST_KEY, item)

    result = audit.verify_chain(limit=100)
    assert result["ok"] is False
    # seq 4 is the first record whose prev_hash no longer matches its predecessor.
    assert result["broken_at"] == 4


def test_list_events_newest_first_and_filtered(audit_redis):
    _emit(5)
    events = audit.list_events(limit=10)
    assert [e["seq"] for e in events] == [5, 4, 3, 2, 1]
    only_c2 = audit.list_events(limit=10, case_id="c2")
    assert [e["case_id"] for e in only_c2] == ["c2"]
    only_user0 = audit.list_events(limit=10, actor="user0")
    assert [e["actor"] for e in only_user0] == ["user0"]
