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


# ── /collector/download ───────────────────────────────────────────────────


def _decode(token):
    from jose import jwt as _jwt

    from config import settings as _settings

    return _jwt.decode(token, _settings.JWT_SECRET, algorithms=[_settings.JWT_ALGORITHM])


def _download(**kw):
    args = dict(
        platform="py",
        case_id=None,
        api_url=None,
        collect=None,
        api_token=None,
        current_user={"username": "tester", "role": "analyst"},
    )
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
    # The caller-supplied session token is NEVER embedded — a scoped upload
    # token (upl claim, bound to the requesting user) is minted instead.
    assert cfg.pop("api_token") != "jwt.token.here"
    assert "jwt.token.here" not in body
    assert cfg == {
        "case_id": "case-42",
        "api_url": "http://192.168.1.10:8000/api/v1",
        "collect": ["evtx", "mft", "prefetch"],
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
    args.setdefault("current_user", {"username": "tester", "role": "analyst"})
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
        # api_token is the server-minted scoped upload token, never "tok".
        cfg = json.loads(zf.read(f"{folder}/config.json"))
        embedded = cfg.pop("api_token")
        assert embedded != "tok"
        payload = _decode(embedded)
        assert payload["upl"] is True and payload["sub"] == "tester"
        assert cfg == {
            "collect": ["evtx", "mft"],
            "output_dir": "./output",
            "case_name": "Acme",
            "api_url": "http://1.2.3.4:8000/api/v1",
            "case_id": "c9",
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
    """Secret containment: a caller-supplied session token is never embedded
    (a server-minted scoped upload token takes its place in config.json), and
    the minted token must not bleed into any other member of the zip."""
    token = "SECRET-JWT-XYZ"
    resp = _package(case_id="c1", api_token=token)
    with _open_zip(resp) as zf:
        for name in zf.namelist():
            data = zf.read(name)
            assert token.encode() not in data, f"session token leaked into {name}"
            if name.endswith("config.json"):
                embedded = json.loads(data)["api_token"]
                assert _decode(embedded)["upl"] is True
            else:
                assert b'"upl"' not in data


# ── fo-uploader config injection ──────────────────────────────────────────────

# Column-aligned assignments — the shape the injector originally hardcoded.
ALIGNED_UPLOADER_SRC = (
    "PRESIGNED_URLS = []\n"
    "MULTIPART_UPLOADS = []\n"
    'ENDPOINT   = ""\n'
    'ACCESS_KEY = ""\n'
    'SECRET_KEY = ""\n'
    'BUCKET     = ""\n'
    'REGION     = ""\n'
    'USE_SSL    = "true"\n'
)

# Single-space assignments with trailing comments — the shape the real
# fo_uploader.py was reformatted to, which the old injector silently missed.
COMMENTED_UPLOADER_SRC = (
    "PRESIGNED_URLS = []  # pre-signed PUT URLs\n"
    "MULTIPART_UPLOADS = []  # multipart sessions\n"
    'ENDPOINT = ""  # S3 endpoint hostname (credentials mode)\n'
    'ACCESS_KEY = ""  # S3 access key        (credentials mode)\n'
    'SECRET_KEY = ""  # S3 secret key        (credentials mode)\n'
    'BUCKET = ""  # S3 bucket name       (credentials mode)\n'
    'REGION = ""  # S3 region            (credentials mode)\n'
    'USE_SSL = "true"  # "true" / "false"     (credentials mode)\n'
)


_CONFIG_NAMES = (
    "PRESIGNED_URLS",
    "MULTIPART_UPLOADS",
    "ENDPOINT",
    "ACCESS_KEY",
    "SECRET_KEY",
    "BUCKET",
    "REGION",
    "USE_SSL",
)


def _exec_config_block(source: str) -> dict:
    """Execute only the injected assignments and return the resulting values.

    Evaluating the real values is the point: a substring assertion passes on a
    template whose placeholder was never rewritten. The rest of the script
    (argparse, boto3) is irrelevant here, so only the assignment lines are run.
    """
    lines = [
        ln
        for ln in source.splitlines()
        if any(ln.startswith(f"{name} =") for name in _CONFIG_NAMES)
    ]
    ns: dict = {}
    exec("\n".join(lines), ns)
    return {name: ns[name] for name in _CONFIG_NAMES if name in ns}


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
    # Both placeholders must be present: injection is strict now, because a
    # template missing one used to ship an unconfigured package silently.
    src = "X = 1\nPRESIGNED_URLS = []\nMULTIPART_UPLOADS = []\n"
    out = co._inject_presigned_config(src, urls)
    ns: dict = {}
    exec(out, ns)
    assert ns["PRESIGNED_URLS"] == urls
    assert ns["MULTIPART_UPLOADS"] == []


@pytest.mark.skipif(not TALON_UPLOADER.exists(), reason="tools/talon not present")
def test_presigned_placeholder_matches_real_talon_uploader():
    src = TALON_UPLOADER.read_text(encoding="utf-8")
    out = co._inject_presigned_config(src, ["https://s3/put1"])
    assert 'PRESIGNED_URLS = ["https://s3/put1"]' in out


@pytest.mark.skipif(not TALON_UPLOADER.exists(), reason="tools/talon not present")
def test_creds_placeholders_match_real_talon_uploader():
    """The packaged script must actually carry the credentials.

    Regression guard: the injector used to search for column-aligned
    placeholders while fo_uploader.py used single-space assignments, so every
    field was silently skipped and the downloaded script exited with "Script is
    not configured". Executing the injected source is the only assertion that
    catches that — a substring check on the template does not.
    """
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
    values = _exec_config_block(out)
    assert values["ENDPOINT"] == "s3.example.com"
    assert values["ACCESS_KEY"] == "AK"
    assert values["SECRET_KEY"] == "SK"
    assert values["BUCKET"] == "b"
    assert values["REGION"] == "r"
    assert values["USE_SSL"] == "true"


@pytest.mark.parametrize("src", [ALIGNED_UPLOADER_SRC, COMMENTED_UPLOADER_SRC])
def test_injection_is_independent_of_template_formatting(src):
    """Aligned or single-space-with-comment: both must inject identically."""
    cfg = {
        "endpoint": "https://s3.example.com:9000",
        "access_key": "AKIAXXXX",
        "secret_key": 'se"cret\\key',
        "bucket": "triage",
        "region": "eu-west-1",
        "use_ssl": False,
    }
    ns: dict = {}
    exec(co._inject_uploader_config(src, cfg), ns)
    assert ns["ENDPOINT"] == cfg["endpoint"]
    assert ns["SECRET_KEY"] == cfg["secret_key"]
    assert ns["BUCKET"] == cfg["bucket"]
    assert ns["REGION"] == cfg["region"]
    assert ns["USE_SSL"] == "false"

    urls = ["https://s3/put1?sig=a&b=c"]
    ns2: dict = {}
    exec(co._inject_presigned_config(src, urls, [{"key": "k"}]), ns2)
    assert ns2["PRESIGNED_URLS"] == urls
    assert ns2["MULTIPART_UPLOADS"] == [{"key": "k"}]


def test_injection_refuses_a_template_missing_a_placeholder():
    """Shipping an unconfigured package is worse than failing the download."""
    with pytest.raises(co.UploaderInjectionError, match="BUCKET"):
        co._inject_uploader_config(
            'ENDPOINT = ""\nACCESS_KEY = ""\nSECRET_KEY = ""\n', {"bucket": "b"}
        )
    with pytest.raises(co.UploaderInjectionError, match="MULTIPART_UPLOADS"):
        co._inject_presigned_config("PRESIGNED_URLS = []\n", ["https://s3/put1"])


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


def _ca_pem() -> bytes:
    """A throwaway self-signed cert — load_verify_locations only needs a
    parseable PEM, and generating one keeps this test hermetic."""
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


# ── Kubernetes API transport must be verified ─────────────────────────────────
#
# _k8s_request sends the pod's service account token as a bearer credential.
# It used to fall back to an unverified TLS context when the cluster CA bundle
# was missing, which handed that token to whatever answered on
# kubernetes.default.svc. A missing CA is now a hard failure.


def test_k8s_request_refuses_to_run_without_the_cluster_ca(monkeypatch, tmp_path):
    token = tmp_path / "token"
    token.write_text("sa-token-value")
    monkeypatch.setattr(co, "_K8S_TOKEN_PATH", token)
    monkeypatch.setattr(co, "_K8S_CA_PATH", tmp_path / "absent-ca.crt")

    def _must_not_connect(*a, **kw):  # pragma: no cover - asserts it isn't hit
        raise AssertionError("connected without verifying the API server")

    monkeypatch.setattr(co.urllib.request, "urlopen", _must_not_connect)

    status, body = co._k8s_request("GET", "/api/v1/namespaces")
    assert status == 0
    assert "CA certificate unavailable" in body["error"]


def test_k8s_request_verifies_when_the_ca_is_present(monkeypatch, tmp_path):
    """With the CA in place the context must verify — not merely load the file."""
    token = tmp_path / "token"
    token.write_text("sa-token-value")
    ca = tmp_path / "ca.crt"
    # Any real PEM works; load_verify_locations only needs a parseable cert.
    ca.write_bytes(_ca_pem())
    monkeypatch.setattr(co, "_K8S_TOKEN_PATH", token)
    monkeypatch.setattr(co, "_K8S_CA_PATH", ca)

    seen = {}

    class _Resp:
        status = 200

        def read(self):
            return b'{"ok": true}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_urlopen(req, context=None, timeout=None):
        seen["ctx"] = context
        seen["auth"] = req.get_header("Authorization")
        return _Resp()

    monkeypatch.setattr(co.urllib.request, "urlopen", _fake_urlopen)

    status, body = co._k8s_request("GET", "/api/v1/namespaces")
    assert (status, body) == (200, {"ok": True})
    assert seen["auth"] == "Bearer sa-token-value"
    ctx = seen["ctx"]
    assert ctx.verify_mode == co.ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


# ── BitLocker recovery key must not reach object storage ──────────────────────
#
# The S3 bootstrap flow packs config.json into the collector zip and uploads it
# to the triage bucket behind a presigned GET URL valid for up to 168 hours.
# A recovery key embedded there is a disk-decryption secret sitting in object
# storage, and the post-collection cleanup is best-effort (a failed DELETE is
# logged, not fatal). The key belongs in the bootstrap script instead, which is
# returned over the authenticated API and never uploaded.


def test_bitlocker_key_is_not_written_into_the_uploaded_config():
    """config.json is the file that goes to S3 — the key must not be in it."""
    src = Path(co.__file__).read_text()
    assert 'config["bitlocker_key"]' not in src, (
        "bitlocker_key is being written into the S3-uploaded config.json again"
    )


def test_bootstrap_scripts_pass_the_key_at_run_time():
    """Both bootstrap flavours must forward it as a --bitlocker-key argument,
    so the capability is preserved without the key leaving the analyst."""
    src = Path(co.__file__).read_text()
    assert "TPLBITLOCKER_KEY" in src
    assert src.count("TPLBITLOCKER_KEY") >= 3          # ps1 + sh + the fill
    assert "--bitlocker-key" in src


def test_the_key_is_script_sanitised_before_interpolation():
    """It lands in a double-quoted shell/PowerShell assignment."""
    src = Path(co.__file__).read_text()
    assert '.replace("TPLBITLOCKER_KEY", _script_safe(' in src
