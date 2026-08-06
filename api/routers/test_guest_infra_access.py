"""Guest-role regression tests: infra/tenant endpoints must reject guests.

GET /companies and GET /metrics/dashboard are mounted under
require_analyst_or_admin, which admits guests — the stricter
require_analyst_plus gate now sits on the endpoints themselves. Guests keep
read access to case data (not exercised here); only these two routes change.
"""

import sys
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import auth.dependencies as auth_deps  # noqa: E402

import routers.companies as companies  # noqa: E402
import routers.metrics as metrics  # noqa: E402

_GUEST = {"username": "g", "role": "guest", "companies": [], "groups": []}
_ANALYST = {"username": "a", "role": "analyst", "companies": [], "groups": []}


def _app(monkeypatch, user, router):
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[auth_deps.get_current_user] = lambda: user
    from fastapi.testclient import TestClient

    return TestClient(app)


@pytest.fixture
def make_client(monkeypatch):
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(companies, "get_redis", lambda: fake)
    return lambda user, router: _app(monkeypatch, user, router)


def test_guest_cannot_list_companies(make_client):
    resp = make_client(_GUEST, companies.router).get("/companies")
    assert resp.status_code == 403


def test_analyst_can_list_companies(make_client):
    resp = make_client(_ANALYST, companies.router).get("/companies")
    assert resp.status_code == 200
    assert resp.json() == {"companies": []}


def test_guest_cannot_read_metrics_dashboard(make_client):
    resp = make_client(_GUEST, metrics.router).get("/metrics/dashboard")
    assert resp.status_code == 403


def test_analyst_can_read_metrics_dashboard(make_client):
    resp = make_client(_ANALYST, metrics.router).get("/metrics/dashboard")
    assert resp.status_code != 403
