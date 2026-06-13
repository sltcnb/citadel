"""Shared pytest fixtures for the api package.

Provides a fakeredis-backed client wired into every module-level Redis accessor
the unit tests touch, so router/service/auth logic can be tested without a live
Redis. We deliberately avoid spinning up the full FastAPI app (it imports native
deps — yara, pytsk3, minio, python-magic — that aren't needed for these tests).
"""

import sys
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))


@pytest.fixture
def fake_redis(monkeypatch):
    """A FakeRedis patched in everywhere the code under test reads Redis.

    decode_responses=True mirrors the real shared pool (config.py), so values
    come back as str — matching what the production code expects.
    """
    fake = fakeredis.FakeRedis(decode_responses=True)

    import auth.service as svc
    import services.cases as cases
    import services.sigma_settings as ss

    # auth.service imports `from config import get_redis as _redis`
    monkeypatch.setattr(svc, "_redis", lambda: fake, raising=True)
    # services.cases / sigma_settings import `get_redis` into their namespace
    monkeypatch.setattr(cases, "get_redis", lambda: fake, raising=True)
    monkeypatch.setattr(ss, "get_redis", lambda: fake, raising=True)

    return fake
