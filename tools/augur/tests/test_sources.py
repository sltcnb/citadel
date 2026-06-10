"""Source tests — all offline via MockSession."""

from __future__ import annotations

import pytest
from augur.models import IOC, IOCType
from augur.sources import AbuseIPDBSource, OTXSource, URLhausSource
from augur.sources.base import SourceError


def test_source_offline_without_session_raises_via_transport():
    src = URLhausSource(session=None)
    with pytest.raises(SourceError):
        src._http_get("https://example.test")


def test_urlhaus_known_url_is_malicious(mock_session):
    sess = mock_session(
        {
            "/url/": {
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["emotet"],
            },
        }
    )
    v = URLhausSource(session=sess).enrich(IOC.parse("http://evil.test/x"))
    assert v.error is None
    assert v.malicious >= 0.9
    assert "emotet" in v.labels
    assert sess.calls and sess.calls[0][0] == "POST"


def test_urlhaus_no_results_is_low_confidence_benign(mock_session):
    sess = mock_session({"/host/": {"query_status": "no_results"}})
    v = URLhausSource(session=sess).enrich(IOC("evil.test", IOCType.DOMAIN))
    assert v.error is None
    assert v.malicious == 0.0
    assert v.confidence < 0.5


def test_abuseipdb_scales_score_and_confidence(mock_session):
    sess = mock_session(
        {
            "abuseipdb.com": {
                "data": {
                    "abuseConfidenceScore": 90,
                    "totalReports": 40,
                    "countryCode": "RU",
                    "isTor": True,
                }
            },
        }
    )
    v = AbuseIPDBSource(api_key="k", session=sess).enrich(IOC("1.2.3.4", IOCType.IP))
    assert v.malicious == pytest.approx(0.9)
    assert v.confidence == 1.0  # capped
    assert "tor-exit-node" in v.labels


def test_abuseipdb_missing_key_errors_without_network():
    v = AbuseIPDBSource(api_key="", session=None).enrich(IOC("1.2.3.4", IOCType.IP))
    assert v.error == "missing api_key"
    assert v.confidence == 0.0


def test_otx_pulse_count_maps_to_score(mock_session):
    sess = mock_session(
        {
            "/file/": {"pulse_info": {"count": 6, "pulses": [{"tags": ["apt29"]}]}},
        }
    )
    ioc = IOC("a" * 64, IOCType.HASH)
    v = OTXSource(api_key="k", session=sess).enrich(ioc)
    assert v.malicious == pytest.approx(1.0)
    assert "apt29" in v.labels


def test_source_http_error_returns_error_verdict(mock_session):
    sess = mock_session({"/url/": {}}, status=503)
    v = URLhausSource(session=sess).enrich(IOC.parse("http://evil.test/x"))
    assert v.error is not None
    assert v.confidence == 0.0
