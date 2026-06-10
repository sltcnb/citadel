"""End-to-end enricher + cache + CLI tests, fully offline."""

from __future__ import annotations

import json

from augur import cli
from augur.cache import TTLCache
from augur.enricher import Enricher
from augur.io import load_iocs
from augur.models import IOC, IOCType
from augur.sources import AbuseIPDBSource, OTXSource, URLhausSource


def _sources(sess):
    return [
        URLhausSource(session=sess),
        AbuseIPDBSource(api_key="k", session=sess),
        OTXSource(api_key="k", session=sess),
    ]


def _routes():
    return {
        "/url/": {"query_status": "ok", "url_status": "online", "threat": "malware_download"},
        "abuseipdb.com": {"data": {"abuseConfidenceScore": 80, "totalReports": 30}},
        "/IPv4/": {"pulse_info": {"count": 4, "pulses": [{"tags": ["botnet"]}]}},
    }


def test_three_sources_fuse_for_an_ip(mock_session):
    sess = mock_session(_routes())
    enr = Enricher(_sources(sess))
    res = enr.enrich_one(IOC("1.2.3.4", IOCType.IP))
    # abuseipdb + otx both answer for IP; urlhaus does not support IP.
    answering = [v.source for v in res.verdicts if v.error is None]
    assert set(answering) == {"abuseipdb", "otx"}
    assert res.score > 0.5
    assert res.severity in ("medium", "high", "critical")


def test_cache_prevents_second_network_call(mock_session):
    sess = mock_session(_routes())
    cache = TTLCache(ttl_seconds=600)
    enr = Enricher(_sources(sess), cache=cache)
    ioc = IOC("1.2.3.4", IOCType.IP)
    enr.enrich_one(ioc)
    calls_after_first = len(sess.calls)
    enr.enrich_one(ioc)
    assert len(sess.calls) == calls_after_first  # served from cache
    assert cache.hits >= 2


def test_cache_ttl_expiry():
    cache = TTLCache(ttl_seconds=100)
    from augur.models import SourceVerdict

    k = ("urlhaus", "ip", "1.2.3.4")
    cache.set(k, SourceVerdict("urlhaus", 0.9, 1.0), now=0.0)
    assert cache.get(k, now=50.0) is not None
    assert cache.get(k, now=101.0) is None  # expired


def test_load_iocs_dedup_and_infer(tmp_path):
    p = tmp_path / "iocs.json"
    p.write_text(
        json.dumps(
            [
                "1.2.3.4",
                "1.2.3.4",  # dup
                {"value": "evil.com", "type": "domain"},
                "http://bad.test/x",
                "a" * 64,
            ]
        )
    )
    iocs = load_iocs(p)
    types = sorted({i.type.value for i in iocs})
    assert "ip" in types and "domain" in types and "url" in types and "hash" in types
    assert sum(1 for i in iocs if i.value == "1.2.3.4") == 1


def test_cli_enrich_writes_valid_bundle(tmp_path, monkeypatch, mock_session):
    # Force every source to use one shared offline mock session.
    sess = mock_session(_routes())
    monkeypatch.setattr(cli, "_build_session", lambda online: sess)

    inp = tmp_path / "iocs.json"
    inp.write_text(json.dumps(["1.2.3.4", "http://evil.test/x"]))
    out = tmp_path / "out.stix.json"

    rc = cli.main(["enrich", str(inp), "-o", str(out), "--online"])
    assert rc == 0

    bundle = json.loads(out.read_text())
    assert bundle["type"] == "bundle"
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 2


def test_cli_offline_default_produces_bundle_with_errors(tmp_path, capsys):
    inp = tmp_path / "iocs.json"
    inp.write_text(json.dumps(["1.2.3.4"]))
    rc = cli.main(["enrich", str(inp)])
    assert rc == 0
    out = capsys.readouterr().out
    bundle = json.loads(out)
    assert bundle["type"] == "bundle"
