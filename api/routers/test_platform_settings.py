"""Unit tests for the platform runtime settings router + resolver.

Uses a fakeredis instance patched into the platform_settings module's Redis
accessor (same pattern as api/conftest.py). The FastAPI app is not booted —
endpoint handlers are called directly with validated Pydantic models.
"""

import fakeredis
import pytest
from fastapi import HTTPException

import routers.platform_settings as ps
from routers.platform_settings import (
    PlatformConfigIn,
    get_platform_config,
    get_platform_config_endpoint,
    update_platform_config,
)


@pytest.fixture
def fake_redis(monkeypatch):
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(ps, "_redis", lambda: fake, raising=True)
    return fake


def _valid_body(**overrides) -> PlatformConfigIn:
    base = {
        "jwt_expire_hours": 12,
        "login_rate_limit": 20,
        "login_rate_window_seconds": 120,
        "agent_max_steps": 30,
        "default_report_language": "fr",
        "max_upload_gib": 5,
        "session_idle_minutes": 15,
    }
    base.update(overrides)
    return PlatformConfigIn(**base)


def test_defaults_when_unset(fake_redis):
    cfg = get_platform_config_endpoint()
    assert cfg["jwt_expire_hours"] == ps._defaults()["jwt_expire_hours"]
    assert cfg["login_rate_limit"] == 10
    assert cfg["login_rate_window_seconds"] == 60
    assert cfg["agent_max_steps"] == 50
    assert cfg["default_report_language"] == "en"
    assert cfg["max_upload_gib"] == 2
    assert cfg["session_idle_minutes"] == 0


def test_put_persists_and_get_reflects(fake_redis):
    out = update_platform_config(_valid_body())
    assert out["jwt_expire_hours"] == 12
    assert out["default_report_language"] == "fr"

    # New read reflects what was persisted.
    cfg = get_platform_config_endpoint()
    assert cfg["login_rate_limit"] == 20
    assert cfg["agent_max_steps"] == 30
    assert cfg["max_upload_gib"] == 5
    assert cfg["session_idle_minutes"] == 15


def test_language_normalized_lowercase(fake_redis):
    out = update_platform_config(_valid_body(default_report_language="ES"))
    assert out["default_report_language"] == "es"


def test_range_validation_rejects_non_positive_int(fake_redis):
    with pytest.raises(HTTPException) as exc:
        update_platform_config(_valid_body(jwt_expire_hours=0))
    assert exc.value.status_code == 422

    with pytest.raises(HTTPException):
        update_platform_config(_valid_body(login_rate_limit=-1))


def test_range_validation_session_idle_allows_zero(fake_redis):
    out = update_platform_config(_valid_body(session_idle_minutes=0))
    assert out["session_idle_minutes"] == 0

    with pytest.raises(HTTPException):
        update_platform_config(_valid_body(session_idle_minutes=-5))


def test_range_validation_rejects_bad_language(fake_redis):
    with pytest.raises(HTTPException) as exc:
        update_platform_config(_valid_body(default_report_language="klingon"))
    assert exc.value.status_code == 422


def test_resolver_redis_over_default(fake_redis):
    # Default before any write.
    assert get_platform_config()["agent_max_steps"] == 50
    # Persist a partial override directly to Redis (only one key set).
    import json

    fake_redis.set(ps._PLATFORM_CONFIG_KEY, json.dumps({"agent_max_steps": 7}))
    cfg = get_platform_config()
    # Overridden key wins; unset keys fall back to defaults.
    assert cfg["agent_max_steps"] == 7
    assert cfg["login_rate_limit"] == 10
    assert cfg["jwt_expire_hours"] == ps._defaults()["jwt_expire_hours"]


def test_resolver_fails_open_on_redis_error(monkeypatch):
    def boom():
        raise RuntimeError("redis down")

    monkeypatch.setattr(ps, "_redis", boom, raising=True)
    cfg = get_platform_config()
    assert cfg == ps._defaults()
