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


@pytest.fixture(autouse=True)
def _isolate_db(tmp_path):
    """Point the DB layer at a fresh per-test sqlite file with NO tables created.

    This mirrors the real degraded path (anchor table absent / migrations not
    applied): ``_read_db_anchor`` returns None and ``_write_db_anchor`` returns
    False, so seals still succeed and verification falls back to genesis + Redis.
    The ``db_anchor`` fixture opts in to an initialised schema on the same engine.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db
    import models  # noqa: F401  (registers models on db.Base.metadata)

    engine = create_engine(
        f"sqlite:///{tmp_path}/seal_test.db",
        future=True,
        connect_args={"check_same_thread": False},
    )
    db.set_sessionmaker(sessionmaker(bind=engine, expire_on_commit=False, future=True))
    yield engine
    db.set_sessionmaker(None)


@pytest.fixture
def db_anchor(_isolate_db):
    """Create the authoritative anchor table on the isolated per-test engine."""
    import db

    db.Base.metadata.create_all(_isolate_db)
    return _isolate_db


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


# ── M2: full verification anchored to genesis ──────────────────────────────────


def test_verify_chain_full_ok_when_anchored():
    chain = _build_chain(3)
    res = es._verify_chain_full(chain)
    assert res["ok"] is True
    assert res["reason"] is None
    assert res["sealed_count"] == 3


def test_verify_chain_full_detects_truncation():
    # Drop the oldest seal: the remaining chain is internally self-consistent
    # (windowed verify would say OK) but is no longer anchored to genesis.
    chain = _build_chain(3)[1:]
    windowed = es._verify_chain(chain)
    assert windowed["ok"] is True  # windowed path still accepts the truncated window

    full = es._verify_chain_full(chain)
    assert full["ok"] is False
    assert full["reason"] == "not_anchored"
    assert full["broken_at"] == 2  # seq of the now-first record


def test_verify_chain_full_still_detects_internal_break():
    chain = _build_chain(3)
    chain[1]["sha256"] = "deadbeef"
    full = es._verify_chain_full(chain)
    assert full["ok"] is False
    assert full["reason"] == "broken"
    assert full["broken_at"] == 2


def test_verify_seals_full_detects_truncation(fake):
    es.seal_artifact("c1", "a1", "AA")
    es.seal_artifact("c1", "a2", "BB")
    es.seal_artifact("c1", "a3", "CC")
    # Truncate the oldest record directly in the store (list is oldest-first).
    fake.lpop(es._list_key("c1"))
    res = es.verify_seals("c1")
    assert res["ok"] is False
    assert res["reason"] == "not_anchored"


# ── Atomic append (compare-and-set) ────────────────────────────────────────────


def test_cas_append_rejects_stale_head(fake):
    """Directly exercise the CAS: a stale observed-head must not append (no fork)."""
    es.seal_artifact("c1", "a1", "AA")
    # Simulate a writer that observed the empty/genesis state but tries to commit
    # after another seal already advanced the head → CAS must return 0.
    applied = fake.eval(
        es._CAS_APPEND,
        3,
        es._list_key("c1"),
        es._head_key("c1"),
        es._anchor_key("c1"),
        "",            # observed_head = empty (stale: chain is non-empty now)
        0,             # observed_len = 0 (stale)
        '{"stale":1}',
        "deadbeef",
        '{"head_hash":"deadbeef","length":1}',
    )
    assert int(applied) == 0
    # Chain untouched and still verifies.
    assert len(es.list_seals("c1")) == 1
    assert es.verify_seals("c1")["ok"] is True


def test_concurrent_appends_do_not_fork(fake, monkeypatch):
    """Interleave two appends that both observe the same head; CAS + retry must
    serialize them into a single linear chain (no duplicate seq, no fork)."""
    real_read = es._read_head_len
    state = {"first": True}

    def racing_read(r, head_key, list_key):
        observed = real_read(r, head_key, list_key)
        if state["first"]:
            # First caller observes the head, then a *second* seal sneaks in and
            # advances the chain before the first caller's CAS runs.
            state["first"] = False
            es.seal_artifact("cX", "sneaky", "SS")
        return observed

    es.seal_artifact("cX", "a0", "AA")  # genesis link
    monkeypatch.setattr(es, "_read_head_len", racing_read, raising=True)
    # This append observes a stale head (the sneaky one races in), so its first
    # CAS misses and it retries against the new head.
    es.seal_artifact("cX", "a1", "BB")

    seals = es.list_seals("cX")  # newest-first
    seqs = sorted(s["seq"] for s in seals)
    assert seqs == [1, 2, 3]            # no duplicate/forked seq
    assert es.verify_seals("cX")["ok"] is True  # single intact chain


# ── Out-of-band anchor cross-check ─────────────────────────────────────────────


def test_anchor_written_on_append(fake):
    es.seal_artifact("c1", "a1", "AA")
    es.seal_artifact("c1", "a2", "BB")
    anchor = es._read_anchor(fake, "c1")
    assert anchor is not None
    assert anchor["length"] == 2
    assert anchor["head_hash"] == es.list_seals("c1")[0]["seal_hash"]


def test_anchor_mismatch_detected(fake):
    """Attacker rewrites the chain list consistently (recomputes hashes) but does
    NOT update the out-of-band anchor → full verification must flag it."""
    es.seal_artifact("c1", "a1", "AA")
    es.seal_artifact("c1", "a2", "BB")

    # Rebuild the whole chain around a tampered payload, recomputing every hash so
    # the chain is INTERNALLY consistent and genesis-anchored.
    forged = _build_chain(2)
    forged[0]["artifact_id"] = "evil"
    forged[0]["seal_hash"] = es._seal_hash(
        es.GENESIS_HASH, {k: v for k, v in forged[0].items() if k != "seal_hash"}
    )
    forged[1]["prev_hash"] = forged[0]["seal_hash"]
    forged[1]["seal_hash"] = es._seal_hash(
        forged[1]["prev_hash"], {k: v for k, v in forged[1].items() if k != "seal_hash"}
    )
    fake.delete(es._list_key("c1"))
    for rec in forged:
        fake.rpush(es._list_key("c1"), json.dumps(rec))
    fake.set(es._head_key("c1"), forged[-1]["seal_hash"])
    # Anchor is NOT updated by the attacker.

    res = es.verify_seals("c1")
    assert res["ok"] is False
    assert res["anchor_ok"] is False
    assert res["reason"] == "anchor_mismatch"
    # No DB anchor configured here → fell back to the Redis anchor.
    assert res["anchor_source"] == "redis"


# ── DB-backed authoritative anchor ──────────────────────────────────────────────


def test_db_anchor_written_on_append(fake, db_anchor):
    es.seal_artifact("c1", "a1", "AA")
    es.seal_artifact("c1", "a2", "BB")
    anchor = es._read_db_anchor("c1")
    assert anchor is not None
    assert anchor["length"] == 2
    assert anchor["head_hash"] == es.list_seals("c1")[0]["seal_hash"]


def test_verify_uses_db_anchor_as_authoritative(fake, db_anchor):
    es.seal_artifact("c1", "a1", "AA")
    es.seal_artifact("c1", "a2", "BB")
    res = es.verify_seals("c1")
    assert res["ok"] is True
    assert res["anchor_ok"] is True
    assert res["anchor_source"] == "db"


def test_verify_detects_rewrite_that_missed_db_anchor(fake, db_anchor):
    """Attacker rewrites BOTH the Redis chain list AND the Redis anchor
    consistently (so the Redis-only check would pass), but cannot touch the
    authoritative DB anchor → full verification must still flag anchor_mismatch."""
    es.seal_artifact("c1", "a1", "AA")
    es.seal_artifact("c1", "a2", "BB")

    # Forge an internally-consistent, genesis-anchored 2-link chain.
    forged = _build_chain(2)
    forged[0]["artifact_id"] = "evil"
    forged[0]["seal_hash"] = es._seal_hash(
        es.GENESIS_HASH, {k: v for k, v in forged[0].items() if k != "seal_hash"}
    )
    forged[1]["prev_hash"] = forged[0]["seal_hash"]
    forged[1]["seal_hash"] = es._seal_hash(
        forged[1]["prev_hash"], {k: v for k, v in forged[1].items() if k != "seal_hash"}
    )
    fake.delete(es._list_key("c1"))
    for rec in forged:
        fake.rpush(es._list_key("c1"), json.dumps(rec))
    fake.set(es._head_key("c1"), forged[-1]["seal_hash"])
    # Attacker ALSO rewrites the Redis anchor to match the forgery.
    fake.set(
        es._anchor_key("c1"),
        es._canonical_json({"head_hash": forged[-1]["seal_hash"], "length": 2}),
    )
    # The DB anchor still records the genuine head → mismatch.

    res = es.verify_seals("c1")
    assert res["ok"] is False
    assert res["anchor_ok"] is False
    assert res["reason"] == "anchor_mismatch"
    assert res["anchor_source"] == "db"


def test_empty_db_anchor_degrades_to_redis(fake):
    """With NO anchor table (migrations not applied), seals still succeed and
    verification degrades to the genesis + Redis checks with lower assurance."""
    # No db_anchor fixture → table absent; _isolate_db keeps it uncreated.
    es.seal_artifact("c1", "a1", "AA")
    es.seal_artifact("c1", "a2", "BB")
    assert es._read_db_anchor("c1") is None  # table absent → degraded

    res = es.verify_seals("c1")
    assert res["ok"] is True
    assert res["anchor_source"] == "redis"


def test_db_write_failure_surfaces_but_seal_succeeds(fake, monkeypatch, caplog):
    """A DB anchor write failure must NOT fail the seal (chain already committed)
    but must be surfaced as a loud integrity warning."""
    import logging

    monkeypatch.setattr(es, "_write_db_anchor", lambda *a, **k: False, raising=True)
    with caplog.at_level(logging.WARNING):
        rec = es.seal_artifact("c1", "a1", "AA")
    assert rec["seq"] == 1  # seal succeeded despite the anchor-write failure
    assert any("INTEGRITY WARNING" in r.message for r in caplog.records)
