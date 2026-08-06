"""Evidence seal input validation + attribution.

The sha256 must be a real SHA-256 hex digest (64 hex chars) — anything else is
rejected with 422 before the seal is recorded. And `sealed_by` must be the
authenticated user (falling back to the case analyst), not the always-empty
`username` field of the case record.
"""

from __future__ import annotations

import sys
from pathlib import Path

import fakeredis
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import services.evidence_seal as seal_svc  # noqa: E402
from auth.dependencies import get_current_user, require_case_access  # noqa: E402

import routers.evidence_seal as es  # noqa: E402

_VALID = "a" * 64


@pytest.fixture
def client(monkeypatch):
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(seal_svc, "get_redis", lambda: fake)
    # No ingest-job records by default — artifact ids stay on the explicit-hash flow.
    monkeypatch.setattr(es.jobs_svc, "get_job", lambda job_id: None)
    app = FastAPI()
    app.include_router(es.router)
    app.dependency_overrides[require_case_access] = lambda: {"case_id": "c1", "analyst": "alice"}
    app.dependency_overrides[get_current_user] = lambda: {"username": "bob", "role": "analyst"}
    return TestClient(app)


def _client_with_job(monkeypatch, job):
    """Client whose artifact_id 'job1' resolves to the given ingest-job record."""
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(seal_svc, "get_redis", lambda: fake)
    monkeypatch.setattr(es.jobs_svc, "get_job", lambda job_id: dict(job) if job_id == "job1" else None)
    app = FastAPI()
    app.include_router(es.router)
    app.dependency_overrides[require_case_access] = lambda: {"case_id": "c1", "analyst": "alice"}
    app.dependency_overrides[get_current_user] = lambda: {"username": "bob", "role": "analyst"}
    return TestClient(app)


def test_seal_rejects_non_hex_sha256(client):
    for bad in ("nothex", "z" * 64, "a" * 63, "a" * 65, ""):
        r = client.post("/cases/c1/evidence/seal", json={"artifact_id": "job1", "sha256": bad})
        assert r.status_code == 422, bad


def test_seal_accepts_valid_sha256_and_attributes_user(client):
    r = client.post("/cases/c1/evidence/seal", json={"artifact_id": "job1", "sha256": _VALID})
    assert r.status_code == 200, r.text
    assert r.json()["seal"]["sealed_by"] == "bob"


def test_seal_falls_back_to_case_analyst(monkeypatch):
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(seal_svc, "get_redis", lambda: fake)
    monkeypatch.setattr(es.jobs_svc, "get_job", lambda job_id: None)
    app = FastAPI()
    app.include_router(es.router)
    app.dependency_overrides[require_case_access] = lambda: {"case_id": "c1", "analyst": "alice"}
    app.dependency_overrides[get_current_user] = lambda: {}
    r = TestClient(app).post("/cases/c1/evidence/seal", json={"artifact_id": "job1", "sha256": _VALID})
    assert r.status_code == 200, r.text
    assert r.json()["seal"]["sealed_by"] == "alice"


# ── Server-side cross-check against the ingest job's recorded hash ────────────


def test_seal_rejects_sha256_mismatch_with_job_record(monkeypatch):
    job = {"job_id": "job1", "case_id": "c1", "sha256": "b" * 64}
    c = _client_with_job(monkeypatch, job)
    r = c.post("/cases/c1/evidence/seal", json={"artifact_id": "job1", "sha256": _VALID})
    assert r.status_code == 422, r.text
    assert "does not match" in r.json()["detail"]


def test_seal_accepts_hash_matching_job_record(monkeypatch):
    job = {"job_id": "job1", "case_id": "c1", "sha256": "b" * 64}
    c = _client_with_job(monkeypatch, job)
    r = c.post("/cases/c1/evidence/seal", json={"artifact_id": "job1", "sha256": "B" * 64})
    assert r.status_code == 200, r.text
    assert r.json()["sealed"] is True


def test_seal_ignores_job_record_from_another_case(monkeypatch):
    # A job id belonging to a different case must not gate this case's seal.
    job = {"job_id": "job1", "case_id": "other-case", "sha256": "b" * 64}
    c = _client_with_job(monkeypatch, job)
    r = c.post("/cases/c1/evidence/seal", json={"artifact_id": "job1", "sha256": _VALID})
    assert r.status_code == 200, r.text


def test_seal_proceeds_when_job_has_no_recorded_hash(monkeypatch):
    # Older jobs predate the recorded sha256 — keep the explicit-hash flow.
    job = {"job_id": "job1", "case_id": "c1"}
    c = _client_with_job(monkeypatch, job)
    r = c.post("/cases/c1/evidence/seal", json={"artifact_id": "job1", "sha256": _VALID})
    assert r.status_code == 200, r.text
