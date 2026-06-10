"""Offline test fixtures: a mock HTTP session that never touches the network."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the package importable without installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class MockResponse:
    def __init__(self, payload: dict, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def json(self) -> dict:
        return self._payload


class MockSession:
    """Routes requests by URL substring to canned payloads.

    Any unrouted request raises, guaranteeing tests stay offline and explicit.
    """

    def __init__(self, routes: dict[str, dict], status: int = 200) -> None:
        self.routes = routes
        self.status = status
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, url: str, **kwargs):  # noqa: ANN003
        self.calls.append((method, url))
        for fragment, payload in self.routes.items():
            if fragment in url:
                return MockResponse(payload, self.status)
        raise AssertionError(f"unrouted request in offline test: {method} {url}")


@pytest.fixture
def mock_session():
    return MockSession
