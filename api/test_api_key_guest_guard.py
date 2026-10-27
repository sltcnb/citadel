"""The guest read-only guard decodes the bearer token itself and fails open on
a decode error. An API key is not a JWT, so without explicit handling a guest's
key would skip the guard entirely."""

import pytest

main = pytest.importorskip("main", reason="api.main import deps unavailable")
from fastapi.testclient import TestClient  # noqa: E402

from auth import api_keys as ak  # noqa: E402
from auth import service as svc  # noqa: E402

_GUARD = "Guest accounts can create cases"


@pytest.fixture
def client(fake_redis, monkeypatch):
    monkeypatch.setattr(main.settings, "AUTH_ENABLED", True)
    return TestClient(main.app, raise_server_exceptions=False)


def test_guest_key_is_write_blocked_outside_cases(client):
    svc.create_user("g", "pw12345!", role="guest")
    key = ak.create_api_key("g", "ci")["key"]
    resp = client.post("/api/v1/companies", json={"name": "x"}, headers={"Authorization": f"Bearer {key}"})
    assert resp.status_code == 403 and _GUARD in resp.text


def test_analyst_key_passes_the_guard(client):
    svc.create_user("a", "pw12345!", role="analyst")
    key = ak.create_api_key("a", "ci")["key"]
    resp = client.post("/api/v1/companies", json={"name": "x"}, headers={"Authorization": f"Bearer {key}"})
    assert _GUARD not in resp.text
