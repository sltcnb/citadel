"""Regression tests for Redis auth wiring in foctl.

Redis runs with --requirepass (see k8s/redis/deployment.yaml), so every
redis-cli call foctl makes must authenticate, and foctl must generate +
substitute the password into the redis-secret. These tests pin all three so
the 'NOAUTH Authentication required.' failure can't silently return.
"""
import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

FOCTL = Path(__file__).resolve().parent.parent / "foctl"


@pytest.fixture(scope="module")
def foctl():
    spec = importlib.util.spec_from_file_location(
        "foctl", FOCTL, loader=SourceFileLoader("foctl", str(FOCTL)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_redis_password_is_generated(foctl):
    assert "redis_password" in foctl.SECRET_GENERATORS
    # non-empty, url-safe (folds into redis://:<pass>@host without escaping)
    val = foctl.SECRET_GENERATORS["redis_password"]()
    assert val and "@" not in val and "/" not in val and ":" not in val


def test_redis_password_substituted(foctl):
    foctl.NS = "citadel"
    subs = foctl.build_substitutions(
        {"secrets": {"redis_password": "s3cret"},
         "access": {"hostname": "h"}, "images": {"registry": "", "tag": "t"}},
        "IfNotPresent",
    )
    assert subs["__FO_REDIS_PASSWORD__"] == "s3cret"


def test_redis_cli_authenticates(foctl, monkeypatch):
    captured = {}
    monkeypatch.setattr(foctl, "NS", "citadel")
    monkeypatch.setattr(foctl, "run",
                        lambda cmd, **kw: captured.update(cmd=cmd, kw=kw))

    foctl.redis_cli(["LLEN", "celery"])
    cmd = captured["cmd"]

    assert cmd[:2] == ["kubectl", "exec"]
    assert "-i" not in cmd
    assert cmd[-3:-1] == ["sh", "-c"]
    inner = cmd[-1]
    assert '-a "$REDIS_PASSWORD"' in inner
    assert "--no-auth-warning" in inner
    assert inner.endswith("LLEN celery")
    # password never appears as a plaintext argv value
    assert not any("s3cret" in str(c) for c in cmd)


def test_redis_cli_interactive_stdin(foctl, monkeypatch):
    captured = {}
    monkeypatch.setattr(foctl, "NS", "citadel")
    monkeypatch.setattr(foctl, "run",
                        lambda cmd, **kw: captured.update(cmd=cmd, kw=kw))

    foctl.redis_cli(["-x", "SET", "k"], interactive=True, stdin_text="payload")

    assert "-i" in captured["cmd"]
    assert captured["kw"]["stdin_text"] == "payload"
