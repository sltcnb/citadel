"""Regression tests for the MinIO credential + placeholder guards in foctl.

MinIO holds the case evidence, so a deployment that never set its own
credentials is readable by anything that can reach port 9000. foctl used to
substitute a literal ``minioadmin`` into the cluster Secret whenever
config.json had no value, which meant "the operator skipped a step" and "the
evidence store is wide open" looked identical.

These tests pin the two guards that closed that:

  * ``_require_secret`` aborts rather than emitting a known-default credential.
  * ``_fill_env_secrets`` treats a ``minioadmin`` value in .env as a
    placeholder to regenerate, so an existing install heals on redeploy.

They also pin the unsubstituted-placeholder guard, which stops a partially
rendered manifest from pushing the literal ``__FO_JWT_SECRET__`` into the
cluster as a real signing key.
"""
import importlib.util
import re
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
    return {"secrets": secrets,
            "access": {"hostname": "h"}, "images": {"registry": "", "tag": "t"}}


# ── _require_secret ───────────────────────────────────────────────────────────

def test_minio_creds_are_generated(foctl):
    for key in ("minio_access_key", "minio_secret_key"):
        assert key in foctl.SECRET_GENERATORS
        val = foctl.SECRET_GENERATORS[key]()
        assert val and val != "minioadmin"


def test_strong_minio_creds_are_substituted(foctl):
    foctl.NS = "citadel"
    subs = foctl.build_substitutions(
        _cfg(minio_access_key="citadel-abc123", minio_secret_key="s3cret-key"),
        "IfNotPresent",
    )
    assert subs["__FO_MINIO_ACCESS_KEY__"] == "citadel-abc123"
    assert subs["__FO_MINIO_SECRET_KEY__"] == "s3cret-key"


@pytest.mark.parametrize("bad", ["minioadmin", "", "   ", "CHANGE_ME"])
def test_insecure_minio_creds_abort_the_deploy(foctl, bad):
    """The old behaviour silently shipped minioadmin into the cluster Secret."""
    foctl.NS = "citadel"
    with pytest.raises(SystemExit):
        foctl.build_substitutions(
            _cfg(minio_access_key=bad, minio_secret_key="fine-secret"),
            "IfNotPresent",
        )
    with pytest.raises(SystemExit):
        foctl.build_substitutions(
            _cfg(minio_access_key="citadel-abc123", minio_secret_key=bad),
            "IfNotPresent",
        )


def test_missing_minio_creds_abort_the_deploy(foctl):
    foctl.NS = "citadel"
    with pytest.raises(SystemExit):
        foctl.build_substitutions(_cfg(), "IfNotPresent")


# ── .env healing ──────────────────────────────────────────────────────────────

def test_fill_env_secrets_replaces_a_minioadmin_value(foctl, tmp_path):
    """An .env copied from the old .env.example carries minioadmin; the API now
    refuses to start on it, so redeploy must rotate it rather than keep it."""
    env = tmp_path / ".env"
    # A complete .env, so the only thing to heal is the minioadmin pair
    # (_fill_env_secrets also appends any required var missing entirely).
    env.write_text(
        "JWT_SECRET=already-set\nELASTIC_PASSWORD=already-set\n"
        "KIBANA_PASSWORD=already-set\nREDIS_PASSWORD=already-set\n"
        "MINIO_ACCESS_KEY=minioadmin\nMINIO_SECRET_KEY=minioadmin\n"
    )

    generated = foctl._fill_env_secrets(env)
    assert sorted(generated) == ["MINIO_ACCESS_KEY", "MINIO_SECRET_KEY"]

    values = dict(
        line.split("=", 1) for line in env.read_text().splitlines() if "=" in line)
    assert values["MINIO_ACCESS_KEY"] not in ("", "minioadmin")
    assert values["MINIO_SECRET_KEY"] not in ("", "minioadmin")

    # Stable across redeploys — rotating on every run would orphan artifacts.
    assert foctl._fill_env_secrets(env) == []


def test_fill_env_secrets_keeps_an_operator_supplied_value(foctl, tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "JWT_SECRET=already-set\nELASTIC_PASSWORD=already-set\n"
        "KIBANA_PASSWORD=already-set\nREDIS_PASSWORD=already-set\n"
        "MINIO_ACCESS_KEY=my-own-key\nMINIO_SECRET_KEY=my-own-secret\n"
    )
    assert foctl._fill_env_secrets(env) == []
    assert "MINIO_ACCESS_KEY=my-own-key" in env.read_text()


# ── unsubstituted placeholders ────────────────────────────────────────────────

def test_every_manifest_placeholder_has_a_substitution(foctl):
    """A __FO_*__ token with no entry in build_substitutions would be applied
    to the cluster verbatim — as a Secret value, in the case of JWT_SECRET."""
    foctl.NS = "citadel"
    subs = foctl.build_substitutions(
        _cfg(minio_access_key="citadel-abc123", minio_secret_key="s3cret-key"),
        "IfNotPresent",
    )
    k8s = Path(__file__).resolve().parent.parent / "k8s"
    missing = {}
    for path in sorted(k8s.rglob("*.yaml")):
        found = set(re.findall(r"__FO_[A-Z0-9_]+__", path.read_text()))
        unknown = found - set(subs)
        if unknown:
            missing[path.name] = sorted(unknown)
    assert not missing, f"manifests reference unknown placeholders: {missing}"
