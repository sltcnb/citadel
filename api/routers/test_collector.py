"""Unit tests for routers/collector.py — evidence-integrity paths.

Follows the api/ colocated-test convention (see test_platform_settings.py /
test_audit.py): no FastAPI app boot, handlers and helpers are called directly,
Redis is fakeredis, and filesystem/subprocess/network access is monkeypatched.

Focus: the zip the analyst hands to a target machine must contain EXACTLY the
intended config (no field loss, no secret leakage outside config.json), config
injection must round-trip faithfully, and network address inference must be
deterministic given known inputs.
"""

import ast
import io
import json
import re
import sys
import zipfile
from datetime import date
from pathlib import Path

import fakeredis
import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import redis_keys as rk  # noqa: E402
import routers.collector as co  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
TALON_COLLECT = REPO_ROOT / "tools" / "talon" / "collect.py"
TALON_UPLOADER = REPO_ROOT / "tools" / "talon" / "fo_uploader.py"

FAKE_COLLECT_SRC = (
    "#!/usr/bin/env python3\n"
    "from __future__ import annotations\n"
    "EMBEDDED_CONFIG: dict = {}\n"
    "def main():\n"
    "    return EMBEDDED_CONFIG\n"
)


def _extract_config(source: str) -> dict:
    """Pull the injected EMBEDDED_CONFIG literal back out of a script."""
    m = re.search(r"EMBEDDED_CONFIG: dict = (.+)", source)
    assert m, "EMBEDDED_CONFIG assignment not found in generated script"
    return ast.literal_eval(m.group(1))


@pytest.fixture
def fake_collect(monkeypatch, tmp_path):
    """A collect.py with the real placeholder, wired into script discovery."""
    p = tmp_path / "collect.py"
    p.write_text(FAKE_COLLECT_SRC, encoding="utf-8")
    monkeypatch.setattr(co, "_find_collect_script", lambda: p, raising=True)
    return p


# ── _inject_config ────────────────────────────────────────────────────────────


def test_inject_config_roundtrips_faithfully():
    cfg = {
        "case_id": "abc123",
        "api_url": "http://10.0.0.5:8000/api/v1",
        "collect": ["evtx", "mft", "file_search"],
        "api_token": 'we"ird\'tok\\en',  # quoting must survive repr()
    }
    out = co._inject_config(FAKE_COLLECT_SRC, cfg)
    assert _extract_config(out) == cfg
    # Only the placeholder line changed — the rest of the script is untouched.
    assert out.replace(f"EMBEDDED_CONFIG: dict = {cfg!r}", "EMBEDDED_CONFIG: dict = {}") == (
        FAKE_COLLECT_SRC
    )


def test_inject_config_without_placeholder_returns_source_unchanged():
    src = "x = 1\n# EMBEDDED_CONFIG: dict = {} (only in a comment, not col 0)\n"
    assert co._inject_config(src, {"case_id": "x"}) == src


@pytest.mark.skipif(not TALON_COLLECT.exists(), reason="tools/talon not present")
def test_inject_pattern_matches_real_talon_collect_script():
    """Contract: the regex actually finds the placeholder in the script that is
    served in production (tools/talon mounted at /app/collector)."""
    src = TALON_COLLECT.read_text(encoding="utf-8")
    assert co._INJECT_PATTERN.search(src) is not None
    injected = co._inject_config(src, {"case_id": "c1"})
    assert _extract_config(injected) == {"case_id": "c1"}


# ── _zwrite permission bits ───────────────────────────────────────────────────


def test_zwrite_preserves_unix_permission_bits():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        co._zwrite(zf, "pkg/run.sh", b"#!/bin/sh\n", exe=True)
        co._zwrite(zf, "pkg/config.json", b"{}", exe=False)
    with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
        assert (zf.getinfo("pkg/run.sh").external_attr >> 16) & 0o777 == 0o755
        assert (zf.getinfo("pkg/config.json").external_attr >> 16) & 0o777 == 0o644
        assert zf.read("pkg/config.json") == b"{}"


# ── /collector/download ───────────────────────────────────────────────────────


def _download(**kw):
    args = dict(platform="py", case_id=None, api_url=None, collect=None, api_token=None)
    args.update(kw)
    return co.download_collector(**args)


def test_download_collector_rejects_unknown_platform(fake_collect):
    with pytest.raises(HTTPException) as exc:
        _download(platform="solaris")
    assert exc.value.status_code == 400


def test_download_collector_injects_exactly_the_requested_config(fake_collect):
    resp = _download(
        platform="win",
        case_id="case-42",
        api_url="http://192.168.1.10:8000/api/v1/",  # trailing slash stripped
        collect=" evtx , mft ,,prefetch ",  # whitespace + empties dropped
        api_token="jwt.token.here",
    )
    body = resp.body.decode("utf-8")
    cfg = _extract_config(body)
    assert cfg == {
        "case_id": "case-42",
        "api_url": "http://192.168.1.10:8000/api/v1",
        "collect": ["evtx", "mft", "prefetch"],
        "api_token": "jwt.token.here",
    }
    assert resp.headers["content-disposition"] == 'attachment; filename="fo-collector.py"'
    assert resp.headers["cache-control"] == "no-store"


def test_download_collector_no_params_embeds_empty_config(fake_collect):
    cfg = _extract_config(_download().body.decode("utf-8"))
    assert cfg == {}


# ── /collector/package (zip construction) ─────────────────────────────────────

_PKG_DEFAULTS = dict(
    categories=None,
    case_name=None,
    path=None,
    disk=None,
    skip_problematic=False,
    fetch_patterns=None,
    fetch_max_files=None,
    fetch_max_mb=None,
    output_dir="./output",
    api_url=None,
    case_id=None,
    api_token=None,
    platform=None,
    upload_mode=None,
    presign_expires_hours=24,
    include_python=None,
)


def _package(**kw):
    args = dict(_PKG_DEFAULTS)
    args.update(kw)
    return co.download_harvester_package(**args)


def _open_zip(resp) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BytesIO(resp.body))


def test_package_zip_has_exact_members_and_faithful_config(fake_collect):
    resp = _package(
        categories="evtx,mft",
        case_name="Acme",
        api_url="http://1.2.3.4:8000/api/v1",
        case_id="c9",
        api_token="tok",
        platform="win",
    )
    folder = f"fo-collector_acme_win_{date.today().isoformat()}"
    with _open_zip(resp) as zf:
        assert set(zf.namelist()) == {
            f"{folder}/fo-harvester.py",
            f"{folder}/config.json",
            f"{folder}/run.bat",
            f"{folder}/run.ps1",
            f"{folder}/run.sh",
            f"{folder}/README.txt",
        }
        # Script is byte-identical to the source (no silent mutation).
        assert zf.read(f"{folder}/fo-harvester.py") == fake_collect.read_bytes()
        # config.json carries exactly what was requested — nothing more.
        cfg = json.loads(zf.read(f"{folder}/config.json"))
        assert cfg == {
            "collect": ["evtx", "mft"],
            "output_dir": "./output",
            "case_name": "Acme",
            "api_url": "http://1.2.3.4:8000/api/v1",
            "case_id": "c9",
            "api_token": "tok",
        }
        # run.sh must survive unzip on unix with its +x bit.
        assert (zf.getinfo(f"{folder}/run.sh").external_attr >> 16) & 0o777 == 0o755
    disp = resp.headers["content-disposition"]
    assert disp == f'attachment; filename="{folder}.zip"'


def test_package_folder_name_is_sanitized(fake_collect):
    resp = _package(case_name='ACME Corp / "Breach"!!', platform="Win 64!")
    with _open_zip(resp) as zf:
        top = {n.split("/")[0] for n in zf.namelist()}
    assert top == {f"fo-collector_acme-corp-breach_win64_{date.today().isoformat()}"}


def test_package_fetch_patterns_enable_file_search(fake_collect):
    resp = _package(
        categories="evtx",
        fetch_patterns="*.ps1\n re:evil.* ,secret.docx",
        fetch_max_files=50,
        fetch_max_mb=10,
    )
    with _open_zip(resp) as zf:
        cfg = json.loads(zf.read([n for n in zf.namelist() if n.endswith("config.json")][0]))
    assert cfg["fetch_patterns"] == ["*.ps1", "re:evil.*", "secret.docx"]
    assert cfg["collect"] == ["evtx", "file_search"]  # auto-added, once
    assert cfg["fetch_max_files"] == 50
    assert cfg["fetch_max_mb"] == 10


def test_package_token_lands_only_in_config_json(fake_collect):
    """Secret containment: the JWT is baked into config.json by design, and must
    not bleed into any other member of the zip."""
    token = "SECRET-JWT-XYZ"
    resp = _package(case_id="c1", api_token=token)
    with _open_zip(resp) as zf:
        for name in zf.namelist():
            data = zf.read(name)
            if name.endswith("config.json"):
                assert token.encode() in data
            else:
                assert token.encode() not in data, f"token leaked into {name}"


# ── fo-uploader config injection ──────────────────────────────────────────────

# Source shaped the way _inject_uploader_config expects (aligned assignments).
ALIGNED_UPLOADER_SRC = (
    "PRESIGNED_URLS = []\n"
    'ENDPOINT   = ""\n'
    'ACCESS_KEY = ""\n'
    'SECRET_KEY = ""\n'
    'BUCKET     = ""\n'
    'REGION     = ""\n'
    'USE_SSL    = "true"\n'
)


def test_inject_uploader_config_injects_all_fields_json_escaped():
    cfg = {
        "endpoint": "https://s3.example.com:9000",
        "access_key": "AKIAXXXX",
        "secret_key": 'se"cret\\key',  # must be JSON-escaped, not raw-pasted
        "bucket": "triage",
        "region": "eu-west-1",
        "use_ssl": False,
    }
    out = co._inject_uploader_config(ALIGNED_UPLOADER_SRC, cfg)
    ns: dict = {}
    exec(out, ns)  # the injected script region must stay valid Python
    assert ns["ENDPOINT"] == cfg["endpoint"]
    assert ns["ACCESS_KEY"] == cfg["access_key"]
    assert ns["SECRET_KEY"] == cfg["secret_key"]
    assert ns["BUCKET"] == cfg["bucket"]
    assert ns["REGION"] == cfg["region"]
    assert ns["USE_SSL"] == "false"


def test_inject_presigned_config_replaces_url_list():
    urls = ["https://s3/put1?sig=a&b=c", "https://s3/put2"]
    out = co._inject_presigned_config("X = 1\nPRESIGNED_URLS = []\n", urls)
    ns: dict = {}
    exec(out, ns)
    assert ns["PRESIGNED_URLS"] == urls


@pytest.mark.skipif(not TALON_UPLOADER.exists(), reason="tools/talon not present")
def test_presigned_placeholder_matches_real_talon_uploader():
    src = TALON_UPLOADER.read_text(encoding="utf-8")
    out = co._inject_presigned_config(src, ["https://s3/put1"])
    assert 'PRESIGNED_URLS = ["https://s3/put1"]' in out


@pytest.mark.skipif(not TALON_UPLOADER.exists(), reason="tools/talon not present")
@pytest.mark.xfail(
    reason="BUG: _inject_uploader_config expects aligned placeholders "
    "('ENDPOINT   = \"\"') but tools/talon/fo_uploader.py (mounted at "
    "/app/collector in docker-compose) uses single-space assignments — "
    "ENDPOINT/BUCKET/REGION/USE_SSL are silently NOT injected in credentials "
    "mode.",
    strict=False,
)
def test_creds_placeholders_match_real_talon_uploader():
    src = TALON_UPLOADER.read_text(encoding="utf-8")
    cfg = {
        "endpoint": "s3.example.com",
        "access_key": "AK",
        "secret_key": "SK",
        "bucket": "b",
        "region": "r",
        "use_ssl": True,
    }
    out = co._inject_uploader_config(src, cfg)
    assert 'ENDPOINT = "s3.example.com"' in out or 'ENDPOINT   = "s3.example.com"' in out
    assert '"b"' in out.split("BUCKET", 1)[1].splitlines()[0]


# ── /collector/uploader (zip with injected creds) ─────────────────────────────


@pytest.fixture
def triage_redis(monkeypatch):
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr("config.get_redis", lambda: fake, raising=True)
    return fake


def test_download_uploader_404_when_unconfigured(triage_redis):
    with pytest.raises(HTTPException) as exc:
        co.download_uploader_package()
    assert exc.value.status_code == 404


def test_download_uploader_zip_contains_injected_creds(triage_redis, monkeypatch, tmp_path):
    s3cfg = {
        "endpoint": "https://s3.example.com",
        "access_key": "AKIA123",
        "secret_key": "sekret",
        "bucket": "triage",
        "region": "us-east-1",
        "use_ssl": True,
    }
    triage_redis.set(rk.S3_TRIAGE_CONFIG, json.dumps(s3cfg))
    up = tmp_path / "fo_uploader.py"
    up.write_text(ALIGNED_UPLOADER_SRC, encoding="utf-8")
    monkeypatch.setattr(co, "_find_uploader_script", lambda: up, raising=True)

    resp = co.download_uploader_package()
    with zipfile.ZipFile(io.BytesIO(resp.body)) as zf:
        assert set(zf.namelist()) == {
            "fo-uploader/fo-uploader.py",
            "fo-uploader/requirements.txt",
            "fo-uploader/run.bat",
            "fo-uploader/run.sh",
            "fo-uploader/README.txt",
        }
        script = zf.read("fo-uploader/fo-uploader.py").decode("utf-8")
        ns: dict = {}
        exec(script, ns)
        assert ns["ACCESS_KEY"] == "AKIA123"
        assert ns["SECRET_KEY"] == "sekret"
        assert ns["ENDPOINT"] == "https://s3.example.com"
        assert ns["BUCKET"] == "triage"
        # The secret is intended for fo-uploader.py ONLY — never the docs/launchers.
        for name in zf.namelist():
            if not name.endswith("fo-uploader.py"):
                assert b"sekret" not in zf.read(name), f"secret leaked into {name}"


# ── Network address inference ─────────────────────────────────────────────────


def test_ip_label_and_only_docker_ips():
    assert co._ip_label("172.17.0.2") == "docker bridge"
    assert co._ip_label("192.168.1.5") == "LAN"
    assert co._ip_label("10.1.2.3") == "private network"
    assert co._ip_label("169.254.0.9") == "link-local"
    assert co._ip_label("8.8.8.8") == "interface"

    assert co._only_docker_ips([{"ip": "172.17.0.2", "iface": "eth0"}]) is True
    assert (
        co._only_docker_ips(
            [{"ip": "172.17.0.2", "iface": "eth0"}, {"ip": "192.168.1.5", "iface": "eth1"}]
        )
        is False
    )
    # Configured public URL and k8s-discovered entries are excluded from the check.
    assert co._only_docker_ips([{"ip": "203.0.113.9", "iface": "FO_PUBLIC_URL"}]) is False
    assert (
        co._only_docker_ips(
            [
                {"ip": "10.96.0.1", "iface": "k8s/default/svc", "k8s": True},
                {"ip": "172.18.0.3", "iface": "eth0"},
            ]
        )
        is True
    )


IP_ADDR_OUT = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0
3: veth1@if12: <BROADCAST,MULTICAST> mtu 1500
    inet 172.17.0.5/16 scope global veth1
"""


def test_parse_ip_addr_and_gateway(monkeypatch):
    def fake_check_output(cmd, **kw):
        if cmd[:2] == ["ip", "addr"]:
            return IP_ADDR_OUT
        if cmd[:2] == ["ip", "route"]:
            return "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n"
        raise AssertionError(cmd)

    monkeypatch.setattr(co.subprocess, "check_output", fake_check_output, raising=True)
    assert co._parse_ip_addr() == [
        {"ip": "192.168.1.100", "iface": "eth0"},  # loopback excluded
        {"ip": "172.17.0.5", "iface": "veth1"},  # @if12 suffix stripped
    ]
    assert co._detect_gateway_ip() == "192.168.1.1"

    monkeypatch.setattr(
        co.subprocess, "check_output", lambda *a, **k: "default dev tun0\n", raising=True
    )
    assert co._detect_gateway_ip() is None  # no 'via' → no gateway IP


def _stub_network(monkeypatch, ips, gateway=None, outbound=None, host_docker=None):
    monkeypatch.setattr(co, "_is_kubernetes", lambda: False, raising=True)
    monkeypatch.setattr(co, "_resolve_host_docker_internal", lambda: host_docker, raising=True)
    monkeypatch.setattr(co, "_parse_ip_addr", lambda: ips, raising=True)
    monkeypatch.setattr(co, "_detect_gateway_ip", lambda: gateway, raising=True)
    monkeypatch.setattr(co, "_detect_outbound_ip", lambda: outbound, raising=True)


def test_network_interfaces_ordering_and_dedup(monkeypatch):
    monkeypatch.setenv("FO_PUBLIC_URL", "https://dfir.example.com:8443")
    _stub_network(
        monkeypatch,
        ips=[{"ip": "192.168.1.50", "iface": "eth0"}, {"ip": "172.18.0.2", "iface": "eth1"}],
        gateway="192.168.1.50",  # duplicate of eth0 — must be deduped
        outbound="192.168.1.50",  # duplicate again
    )
    out = co.get_network_interfaces()
    # Configured URL always first, with /api/v1 appended once.
    assert out["candidates"][0]["url"] == "https://dfir.example.com:8443/api/v1"
    assert out["candidates"][0]["iface"] == "FO_PUBLIC_URL"
    ips = [c["ip"] for c in out["candidates"]]
    assert ips == ["dfir.example.com", "192.168.1.50", "172.18.0.2"]  # dedup, order kept
    lan = out["candidates"][1]
    assert lan["url"] == f"http://192.168.1.50:{co._API_PORT}/api/v1"
    assert lan["label"] == "LAN"
    assert out["only_docker_ips"] is False
    assert out["public_url_hint"] is None
    assert out["port"] == int(co._API_PORT)


def test_network_interfaces_docker_only_sets_hint(monkeypatch):
    monkeypatch.delenv("FO_PUBLIC_URL", raising=False)
    _stub_network(monkeypatch, ips=[{"ip": "172.18.0.2", "iface": "eth0"}], gateway="172.18.0.1")
    out = co.get_network_interfaces()
    assert out["only_docker_ips"] is True
    assert "FO_PUBLIC_URL" in out["public_url_hint"]
