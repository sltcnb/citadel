"""App-import smoke test: the FastAPI app boots and /health responds.

Skipped automatically when optional native deps (yara/pytsk3/etc.) or local
tool packages aren't importable in the current environment.
"""

import pytest

main = pytest.importorskip("main", reason="api.main import deps unavailable")
from fastapi.testclient import TestClient  # noqa: E402


def test_health_ok():
    client = TestClient(main.app)
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
