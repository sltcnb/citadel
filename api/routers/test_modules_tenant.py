"""Tenant-isolation regression tests for the module artifact & log-stream
endpoints (api/routers/modules.py).

  * GET  /cases/{case_id}/modules/{run_id}/artifacts/{filename}
  * POST /cases/{case_id}/modules/{run_id}/artifacts/{filename}/reingest
  * GET  /module-runs/{run_id}/log-stream

The first two mint presigned MinIO URLs / ingest jobs from caller-supplied
path parts with no case-access check and no run↔case binding; the SSE
endpoint streamed any run's logs without _check_run_case_access. Setup
follows test_pilot_agent.py's minimal-app tenant pattern.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import auth.dependencies as auth_deps  # noqa: E402
import services.cases as cases_svc  # noqa: E402

import routers.modules as modules  # noqa: E402

_CASE_A = {"id": "caseA", "case_id": "caseA", "name": "A", "company": "companyA"}
_USER_B = {"username": "bob", "role": "analyst", "companies": ["companyB"], "groups": []}
_USER_A = {"username": "amy", "role": "analyst", "companies": ["companyA"], "groups": []}


def _modules_app(monkeypatch, user, case, run):
    """Minimal app hosting the modules router with auth/case/run stubbed."""
    from fastapi import FastAPI

    # require_case_access imports get_case from services.cases at call time…
    monkeypatch.setattr(cases_svc, "get_case", lambda cid: case)
    # …while _check_run_case_access uses the name bound in routers.modules.
    monkeypatch.setattr(modules, "get_case", lambda cid: case)
    monkeypatch.setattr(modules.run_svc, "get_module_run", lambda rid: run)
    app = FastAPI()
    app.include_router(modules.router)
    app.dependency_overrides[auth_deps.get_current_user] = lambda: user
    return app


@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient

    run = {"run_id": "run1", "case_id": "caseA", "module_id": "yara", "status": "COMPLETED"}

    def make(user, case=_CASE_A, run=run):
        return TestClient(_modules_app(monkeypatch, user, case, run), raise_server_exceptions=True)

    return make


# ── artifact download ─────────────────────────────────────────────────────────


def test_artifact_download_cross_company_is_403(client):
    c = client(_USER_B)
    resp = c.get("/cases/caseA/modules/run1/artifacts/out.bin")
    assert resp.status_code == 403


def test_artifact_download_unknown_case_is_404(client):
    c = client(_USER_A, case=None)
    resp = c.get("/cases/caseX/modules/run1/artifacts/out.bin")
    assert resp.status_code == 404


def test_artifact_download_run_from_another_case_is_404(client):
    """Same-company user, but the run_id belongs to a different case — the
    presigned URL must not be minted."""
    c = client(_USER_A, run={"run_id": "run9", "case_id": "caseOther"})
    resp = c.get("/cases/caseA/modules/run9/artifacts/out.bin")
    assert resp.status_code == 404


def test_artifact_download_unknown_run_is_404(client):
    c = client(_USER_A, run=None)
    resp = c.get("/cases/caseA/modules/runX/artifacts/out.bin")
    assert resp.status_code == 404


# ── artifact reingest ─────────────────────────────────────────────────────────


def test_artifact_reingest_cross_company_is_403(client):
    c = client(_USER_B)
    resp = c.post("/cases/caseA/modules/run1/artifacts/out.bin/reingest")
    assert resp.status_code == 403


def test_artifact_reingest_run_from_another_case_is_404(client):
    c = client(_USER_A, run={"run_id": "run9", "case_id": "caseOther"})
    resp = c.post("/cases/caseA/modules/run9/artifacts/out.bin/reingest")
    assert resp.status_code == 404


# ── SSE log stream ────────────────────────────────────────────────────────────


def test_log_stream_cross_company_is_403(client):
    c = client(_USER_B)
    resp = c.get("/module-runs/run1/log-stream")
    assert resp.status_code == 403


def test_log_stream_unknown_run_is_404(client):
    c = client(_USER_B, run=None)
    resp = c.get("/module-runs/runX/log-stream")
    assert resp.status_code == 404
