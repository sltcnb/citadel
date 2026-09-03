"""Regression tests for Elasticsearch auth wiring in foctl.

ES runs with xpack security enabled, so every post-deploy call foctl makes
(cluster health, index template, alias back-fill, kibana_system password) must
authenticate, and foctl must generate + substitute es_password/kibana_password
into elasticsearch-secret. These tests pin that so the '401 → template never
applied / Kibana crash-loop' failures can't silently return.
"""
import importlib.util
import json
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


def _cfg(**secrets):
    # minio_access_key/minio_secret_key are REQUIRED by build_substitutions —
    # it refuses to render a manifest with unset or minioadmin credentials
    # (see test_foctl_minio_creds.py). Supply throwaway ones so these tests
    # exercise only the ES wiring.
    secrets.setdefault("minio_access_key", "citadel-test")
    secrets.setdefault("minio_secret_key", "test-minio-secret")
    return {"secrets": secrets,
            "access": {"hostname": "h"}, "images": {"registry": "", "tag": "t"}}


def test_es_passwords_are_generated(foctl):
    for key in ("es_password", "kibana_password"):
        assert key in foctl.SECRET_GENERATORS
        val = foctl.SECRET_GENERATORS[key]()
        assert val and "@" not in val and "/" not in val and ":" not in val


def test_es_passwords_substituted(foctl):
    foctl.NS = "citadel"
    subs = foctl.build_substitutions(
        _cfg(es_password="es-s3cret", kibana_password="kb-s3cret"),
        "IfNotPresent",
    )
    assert subs["__FO_ES_PASSWORD__"] == "es-s3cret"
    assert subs["__FO_KIBANA_PASSWORD__"] == "kb-s3cret"


def test_wait_for_elasticsearch_authenticates(foctl, monkeypatch):
    captured = {}
    monkeypatch.setattr(foctl, "NS", "citadel")
    monkeypatch.setattr(foctl.time, "sleep", lambda *_: None)
    monkeypatch.setattr(
        foctl, "run",
        lambda cmd, **kw: captured.update(cmd=cmd) or type(
            "R", (), {"returncode": 0, "stdout": "", "stderr": ""})())

    foctl.wait_for_elasticsearch()
    cmd = captured["cmd"]

    assert cmd[:2] == ["kubectl", "exec"]
    inner = cmd[-1]
    assert cmd[-3:-1] == ["sh", "-c"]
    assert '-u "elastic:$ELASTIC_PASSWORD"' in inner
    assert "_cluster/health" in inner
    # password comes from the pod's env — never a plaintext argv value
    assert not any("s3cret" in str(c) for c in cmd)


def test_apply_es_template_authenticates_via_stdin(foctl, monkeypatch):
    captured = {}
    monkeypatch.setattr(foctl, "NS", "citadel")
    monkeypatch.setattr(foctl, "backfill_aliases_in_pod", lambda tmpl: None)
    monkeypatch.setattr(
        foctl, "run",
        lambda cmd, **kw: captured.update(cmd=cmd, kw=kw) or type(
            "R", (), {"returncode": 0, "stdout": "", "stderr": ""})())

    foctl.apply_es_template()
    cmd, kw = captured["cmd"], captured["kw"]

    inner = cmd[-1]
    assert '-u "elastic:$ELASTIC_PASSWORD"' in inner
    assert "_index_template/fo-cases-template" in inner
    # template is piped on stdin, not baked into argv
    assert "-d @-" in inner
    assert kw.get("stdin_text")


def test_set_kibana_system_password(foctl, monkeypatch):
    calls = []
    monkeypatch.setattr(foctl, "NS", "citadel")
    monkeypatch.setattr(
        foctl, "run",
        lambda cmd, **kw: calls.append((cmd, kw)) or type(
            "R", (), {"returncode": 0, "stdout": "", "stderr": ""})())

    foctl.set_kibana_system_password(_cfg(kibana_password="kb-s3cret"))
    cmd, kw = calls[0]

    inner = cmd[-1]
    assert '-u "elastic:$ELASTIC_PASSWORD"' in inner
    assert "_security/user/kibana_system/_password" in inner
    assert json.loads(kw["stdin_text"]) == {"password": "kb-s3cret"}
    # password never appears as a plaintext argv value
    assert not any("kb-s3cret" in str(c) for c in cmd)
    # kibana is restarted afterwards so a crash-looping pod reconnects
    assert any(
        any("rollout" in str(x) for x in c) and any("kibana" in str(x) for x in c)
        for c, _ in calls[1:])


def test_set_kibana_system_password_skips_without_secret(foctl, monkeypatch):
    calls = []
    monkeypatch.setattr(
        foctl, "run",
        lambda cmd, **kw: calls.append(cmd))
    foctl.set_kibana_system_password(_cfg())
    assert calls == []


def test_fill_env_secrets_generates_and_is_stable(foctl, tmp_path):
    env = tmp_path / ".env"
    env.write_text("JWT_SECRET=\nELASTIC_PASSWORD=\nKIBANA_PASSWORD=\n"
                   "REDIS_PASSWORD=\nMINIO_ACCESS_KEY=\nMINIO_SECRET_KEY=\n"
                   "PROXY_PORT=80\n")

    generated = foctl._fill_env_secrets(env)
    assert sorted(generated) == [
        "ELASTIC_PASSWORD", "JWT_SECRET", "KIBANA_PASSWORD",
        "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY", "REDIS_PASSWORD"]

    values = dict(
        line.split("=", 1) for line in env.read_text().splitlines() if "=" in line)
    for key in generated:
        assert values[key], f"{key} still empty"
    assert values["PROXY_PORT"] == "80"

    # second run is a no-op — secrets stay stable across redeploys
    assert foctl._fill_env_secrets(env) == []


def test_fill_env_secrets_appends_missing_vars(foctl, tmp_path):
    env = tmp_path / ".env"
    env.write_text("PROXY_PORT=80\n")
    foctl._fill_env_secrets(env)
    values = dict(
        line.split("=", 1) for line in env.read_text().splitlines() if "=" in line)
    for key in foctl.ENV_SECRET_GENERATORS:
        assert values.get(key), f"{key} not appended"


def test_backfill_script_authenticates(foctl):
    # The in-pod alias back-fill must send an Authorization header built from
    # the api pod's ES env credentials (xpack security on).
    assert "Authorization" in foctl._BACKFILL_PY
    assert "ELASTICSEARCH_PASSWORD" in foctl._BACKFILL_PY
