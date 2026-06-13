"""Tests for the Sigma detection-rules opt-out resolution.

Precedence: per-case override > global runtime setting > SIGMA_ENABLED env.

Uses a minimal in-memory Redis stub (only the ops sigma_settings touches) so the
test needs no running Redis and no fakeredis dependency.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from services import sigma_settings as ss  # noqa: E402


class FakeRedis:
    def __init__(self):
        self.kv: dict[str, str] = {}
        self.hashes: dict[str, dict[str, str]] = {}

    def get(self, k):
        return self.kv.get(k)

    def set(self, k, v):
        self.kv[k] = str(v)

    def hget(self, k, f):
        return self.hashes.get(k, {}).get(f)

    def hset(self, k, f, v):
        self.hashes.setdefault(k, {})[f] = str(v)

    def hdel(self, k, f):
        self.hashes.get(k, {}).pop(f, None)


@pytest.fixture
def fake(monkeypatch):
    r = FakeRedis()
    monkeypatch.setattr(ss, "get_redis", lambda: r)
    return r


def _set_env_default(monkeypatch, value: bool):
    monkeypatch.setattr(ss.settings, "SIGMA_ENABLED", value)


# ── Global resolution ─────────────────────────────────────────────────────────


def test_global_falls_back_to_env_when_unset(fake, monkeypatch):
    _set_env_default(monkeypatch, True)
    assert ss.get_global_sigma_enabled() is True
    _set_env_default(monkeypatch, False)
    assert ss.get_global_sigma_enabled() is False


def test_global_override_beats_env(fake, monkeypatch):
    _set_env_default(monkeypatch, False)  # env says off
    ss.set_global_sigma_enabled(True)     # admin turns it on
    assert ss.get_global_sigma_enabled() is True
    ss.set_global_sigma_enabled(False)
    _set_env_default(monkeypatch, True)   # env says on, override says off
    assert ss.get_global_sigma_enabled() is False


def test_global_read_fails_open_to_env(monkeypatch):
    class Boom:
        def get(self, k):
            raise RuntimeError("redis down")

    monkeypatch.setattr(ss, "get_redis", lambda: Boom())
    _set_env_default(monkeypatch, True)
    assert ss.get_global_sigma_enabled() is True


# ── Per-case override ───────────────────────────────────────────────────────────


def test_case_inherits_global_when_no_override(fake, monkeypatch):
    _set_env_default(monkeypatch, True)
    assert ss.get_case_sigma_override("c1") is None
    assert ss.sigma_enabled_for_case("c1") is True
    ss.set_global_sigma_enabled(False)
    assert ss.sigma_enabled_for_case("c1") is False


def test_case_override_beats_global(fake, monkeypatch):
    _set_env_default(monkeypatch, True)
    ss.set_global_sigma_enabled(True)
    ss.set_case_sigma_override("c1", False)   # case opts out
    assert ss.get_case_sigma_override("c1") is False
    assert ss.sigma_enabled_for_case("c1") is False
    # A different case still inherits the global default.
    assert ss.sigma_enabled_for_case("c2") is True


def test_case_override_can_force_enable_against_disabled_global(fake):
    ss.set_global_sigma_enabled(False)
    ss.set_case_sigma_override("c1", True)
    assert ss.sigma_enabled_for_case("c1") is True


def test_clearing_override_restores_inheritance(fake):
    ss.set_global_sigma_enabled(True)
    ss.set_case_sigma_override("c1", False)
    assert ss.sigma_enabled_for_case("c1") is False
    ss.set_case_sigma_override("c1", None)    # clear → inherit
    assert ss.get_case_sigma_override("c1") is None
    assert ss.sigma_enabled_for_case("c1") is True


# ── Rule classification ─────────────────────────────────────────────────────────


def test_is_sigma_rule():
    assert ss.is_sigma_rule({"rule_type": "sigma"}) is True
    assert ss.is_sigma_rule({"sigma_yaml": "title: x"}) is True
    assert ss.is_sigma_rule({"rule_type": "custom"}) is False
    assert ss.is_sigma_rule({"rule_type": "legacy"}) is False
    assert ss.is_sigma_rule({}) is False
