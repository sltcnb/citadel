"""SSRF guard at webhook DELIVERY time (tasks/_webhooks.py).

The API validates the webhook URL at create/update/test, but DNS can be
rebound afterwards — the worker must resolve and re-check the host before
POSTing. Runs against an in-memory fake Redis; no broker needed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_WORKER_ROOT = Path(__file__).resolve().parents[1]
_TASKS_DIR = _WORKER_ROOT / "tasks"

for _p in (str(_WORKER_ROOT), str(_TASKS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import _webhooks as wh
    import redis_keys as rk
except ModuleNotFoundError:
    pytest.skip("_webhooks' dependency chain is unavailable", allow_module_level=True)


class _FakeRedis:
    def __init__(self, hooks: dict[str, dict]) -> None:
        self._hooks = {k: json.dumps(v) for k, v in hooks.items()}

    def hgetall(self, key):
        return dict(self._hooks) if key == rk.WEBHOOKS else {}


def _hook(url: str) -> dict:
    return {
        "id": "h1",
        "name": "hook",
        "url": url,
        "enabled": True,
        "events": ["alert_rules"],
    }


def test_ssrf_check_rejects_literal_private_ip():
    assert wh._ssrf_check("http://169.254.169.254/latest/meta-data") is not None
    assert wh._ssrf_check("http://127.0.0.1:9200/") is not None
    assert wh._ssrf_check("http://10.0.0.5/hook") is not None


def test_ssrf_check_rejects_localhost_and_internal_names():
    assert wh._ssrf_check("http://localhost/hook") is not None
    assert wh._ssrf_check("http://redis.internal/hook") is not None
    assert wh._ssrf_check("http://printer.local/hook") is not None


def test_ssrf_check_rejects_non_http_schemes():
    assert wh._ssrf_check("file:///etc/passwd") is not None
    assert wh._ssrf_check("gopher://example.com/") is not None


def test_ssrf_check_rejects_host_rebinding_to_private(monkeypatch):
    """A hostname that resolved publicly at config time but now resolves
    private must be refused at delivery."""
    monkeypatch.setattr(
        wh.socket,
        "getaddrinfo",
        lambda host, port: [(2, 1, 6, "", ("192.168.1.10", 0))],
    )
    assert wh._ssrf_check("https://hooks.example.com/abc") is not None


def test_ssrf_check_allows_public_host(monkeypatch):
    monkeypatch.setattr(
        wh.socket,
        "getaddrinfo",
        lambda host, port: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    assert wh._ssrf_check("https://hooks.example.com/abc") is None


def test_delivery_skips_now_private_host(monkeypatch):
    """fire_webhooks must not POST when the host fails the delivery-time
    re-check — the request must never be attempted."""
    monkeypatch.setattr(
        wh.socket,
        "getaddrinfo",
        lambda host, port: [(2, 1, 6, "", ("169.254.169.254", 0))],
    )
    attempted = []

    class _Boom:
        def __call__(self, req, timeout=0):
            attempted.append(req.full_url)
            raise AssertionError("urlopen must not be attempted")

    monkeypatch.setattr(wh.urllib.request, "urlopen", _Boom())

    r = _FakeRedis({"h1": _hook("https://hooks.example.com/abc")})
    wh.fire_webhooks(r, "alert_rules", {"text": "x"})
    assert attempted == []


def test_delivery_posts_to_public_host(monkeypatch):
    monkeypatch.setattr(
        wh.socket,
        "getaddrinfo",
        lambda host, port: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    attempted = []

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        wh.urllib.request,
        "urlopen",
        lambda req, timeout=0: attempted.append(req.full_url) or _Resp(),
    )

    r = _FakeRedis({"h1": _hook("https://hooks.example.com/abc")})
    wh.fire_webhooks(r, "alert_rules", {"text": "x"})
    assert attempted == ["https://hooks.example.com/abc"]
