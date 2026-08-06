"""Worker-side plugin hot-reload tests.

The API INCRs rk.PLUGINS_VERSION on plugin upload/edit; the worker compares it
before picking a parser and reloads its module-level plugin loader only when
the value changed. Uses the conftest FakeRedis — no broker needed.
"""

from __future__ import annotations

import pytest
import redis_keys as rk
from tasks import ingest_task


@pytest.fixture
def reload_spy(monkeypatch):
    """Replace loader.reload() with a counter and reset the seen-version."""
    calls: list[int] = []
    monkeypatch.setattr(ingest_task._plugin_loader, "reload", lambda: calls.append(1))
    monkeypatch.setattr(ingest_task, "_plugins_version_seen", None)
    return calls


def test_no_version_key_means_no_reload(reload_spy, fake_redis):
    ingest_task._maybe_reload_plugins(fake_redis)
    assert reload_spy == []


def test_reload_on_first_seen_version(reload_spy, fake_redis):
    fake_redis.set(rk.PLUGINS_VERSION, "1")
    ingest_task._maybe_reload_plugins(fake_redis)
    assert reload_spy == [1]


def test_no_reload_while_version_unchanged(reload_spy, fake_redis):
    fake_redis.set(rk.PLUGINS_VERSION, "1")
    ingest_task._maybe_reload_plugins(fake_redis)
    ingest_task._maybe_reload_plugins(fake_redis)
    assert reload_spy == [1]


def test_reload_again_on_version_bump(reload_spy, fake_redis):
    fake_redis.set(rk.PLUGINS_VERSION, "1")
    ingest_task._maybe_reload_plugins(fake_redis)
    fake_redis.incr(rk.PLUGINS_VERSION)
    ingest_task._maybe_reload_plugins(fake_redis)
    assert reload_spy == [1, 1]


def test_redis_failure_never_blocks_ingestion(reload_spy):
    class _Boom:
        def get(self, key):
            raise ConnectionError("redis down")

    ingest_task._maybe_reload_plugins(_Boom())  # must not raise
    assert reload_spy == []
