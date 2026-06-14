"""Tests for the court-ready signed evidence chain (services/evidence_seal.py).

Pure helpers are tested directly; Redis-backed flows use a fakeredis monkeypatched
into ``evidence_seal.get_redis`` (mirrors the conftest fake_redis pattern).
"""

from __future__ import annotations

import json

import fakeredis
import pytest

import services.evidence_seal as es


@pytest.fixture
def fake(monkeypatch):
    r = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(es, "get_redis", lambda: r, raising=True)
    return r


# ── Pure helpers ──────────────────────────────────────────────────────────────


def test_seal_hash_depends_on_prev_and_record():
    rec = {"seq": 1, "sha256": "abc", "prev_hash": es.GENESIS_HASH}
    h1 = es._seal_hash(es.GENESIS_HASH, rec)
    # Same input → deterministic.
    assert h1 == es._seal_hash(es.GENESIS_HASH, rec)
    # Different prev_hash → different hash (chain dependence).
    assert h1 != es._seal_hash("f" * 64, rec)
    # Different record content → different hash.
    assert h1 != es._seal_hash(es.GENESIS_HASH, {**rec, "sha256": "xyz"})


def _build_chain(n: int) -> list[dict]:
    """Construct a valid n-link chain using the production hashing helper."""
    chain: list[dict] = []
    prev = es.GENESIS_HASH
    for i in range(1, n + 1):
        without = {
            "seq": i,
            "case_id": "c1",
            "artifact_id": f"a{i}",
            "sha256": f"{i:064x}",
            "sealed_at": f"2026-01-0{i}T00:00:00+00:00",
            "sealed_by": "tester",
            "meta": {},
            "prev_hash": prev,
        }
        h = es._seal_hash(prev, without)
        chain.append({**without, "seal_hash": h})
        prev = h
    return chain


def test_verify_chain_intact():
    chain = _build_chain(3)
    res = es._verify_chain(chain)
    assert res == {"ok": True, "broken_at": None, "sealed_count": 3}


def test_verify_chain_detects_tamper():
    chain = _build_chain(3)
    # Tamper the middle record's payload without recomputing its hash.
    chain[1]["sha256"] = "deadbeef"
    res = es._verify_chain(chain)
    assert res["ok"] is False
    assert res["broken_at"] == 2  # seq of the first broken seal


def test_verify_chain_detects_broken_link():
    chain = _build_chain(3)
    # Break continuity: third record points at a wrong prev_hash but keeps a
    # self-consistent seal_hash, so only the prev_hash continuity check catches it.
    chain[2]["prev_hash"] = "a" * 64
    chain[2]["seal_hash"] = es._seal_hash(
        "a" * 64, {k: v for k, v in chain[2].items() if k != "seal_hash"}
    )
    res = es._verify_chain(chain)
    assert res["ok"] is False
    assert res["broken_at"] == 3


def test_manifest_hash_deterministic_and_sensitive():
    chain = _build_chain(2)
    h = es._manifest_hash(chain)
    assert h == es._manifest_hash(chain)  # deterministic
    tampered = json.loads(json.dumps(chain))
    tampered[0]["sha256"] = "changed"
    assert es._manifest_hash(tampered) != h  # changes when a seal changes


# ── Redis-backed flows ────────────────────────────────────────────────────────


def test_seal_artifact_chains(fake):
    s1 = es.seal_artifact("c1", "a1", "AA", sealed_by="u")
    s2 = es.seal_artifact("c1", "a2", "BB", sealed_by="u")
    assert s1["seq"] == 1 and s2["seq"] == 2
    assert s1["prev_hash"] == es.GENESIS_HASH
    assert s2["prev_hash"] == s1["seal_hash"]  # each hash depends on prev
    # sha256 normalized to lowercase.
    assert s1["sha256"] == "aa"


def test_seal_artifact_per_case_isolation(fake):
    es.seal_artifact("c1", "a1", "AA")
    es.seal_artifact("c2", "b1", "BB")
    assert len(es.list_seals("c1")) == 1
    assert len(es.list_seals("c2")) == 1


def test_list_seals_newest_first(fake):
    es.seal_artifact("c1", "a1", "AA")
    es.seal_artifact("c1", "a2", "BB")
    seals = es.list_seals("c1")
    assert [s["artifact_id"] for s in seals] == ["a2", "a1"]


def test_verify_seals_ok_when_intact(fake):
    es.seal_artifact("c1", "a1", "AA")
    es.seal_artifact("c1", "a2", "BB")
    res = es.verify_seals("c1")
    assert res["ok"] is True
    assert res["broken_at"] is None
    assert res["sealed_count"] == 2
    assert "verified_at" in res


def test_verify_seals_detects_store_tamper(fake):
    es.seal_artifact("c1", "a1", "AA")
    es.seal_artifact("c1", "a2", "BB")
    # Tamper a record directly in the Redis store (oldest-first list, index 0).
    raw = fake.lrange(es._list_key("c1"), 0, -1)
    rec = json.loads(raw[0])
    rec["sha256"] = "tampered"
    fake.lset(es._list_key("c1"), 0, json.dumps(rec))

    res = es.verify_seals("c1")
    assert res["ok"] is False
    assert res["broken_at"] == 1


def test_manifest_unsigned_without_key(fake, monkeypatch):
    monkeypatch.delenv("EVIDENCE_SIGNING_KEY", raising=False)
    es.seal_artifact("c1", "a1", "AA")
    m = es.custody_manifest("c1")
    assert m["signed"] is False
    assert m["signature"] is None
    assert m["chain_intact"] is True
    assert m["sealed_count"] == 1
    assert m["chain_head"] == m["seals"][-1]["seal_hash"]
    assert "recompute" in m["verification_instruction"].lower()


def test_manifest_signed_with_key(fake, monkeypatch):
    import hashlib
    import hmac

    monkeypatch.setenv("EVIDENCE_SIGNING_KEY", "s3cret")
    es.seal_artifact("c1", "a1", "AA")
    m = es.custody_manifest("c1")
    assert m["signed"] is True
    assert m["algorithm"] == "HMAC-SHA256"
    expected = hmac.new(b"s3cret", m["manifest_hash"].encode(), hashlib.sha256).hexdigest()
    assert m["signature"] == expected


def test_manifest_hash_changes_when_seal_changes(fake):
    es.seal_artifact("c1", "a1", "AA")
    h1 = es.custody_manifest("c1")["manifest_hash"]
    es.seal_artifact("c1", "a2", "BB")
    h2 = es.custody_manifest("c1")["manifest_hash"]
    assert h1 != h2
