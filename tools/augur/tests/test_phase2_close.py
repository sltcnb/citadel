"""Phase-2 gap-closure tests: 5+ sources + MISP round-trip. Offline.

Runnable standalone (`python3 tests/test_phase2_close.py`) and under pytest.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from augur import misp  # noqa: E402
from augur.models import IOC, EnrichedIOC, IOCType  # noqa: E402
from augur.sources import BUILTIN_SOURCES, GreyNoiseSource, ShodanSource  # noqa: E402


class _Resp:
    def __init__(self, payload, status=200):
        self._p, self.status_code = payload, status

    def json(self):
        return self._p


class _Sess:
    def __init__(self, routes, status=200):
        self.routes, self.status, self.calls = routes, status, []

    def request(self, method, url, **kw):
        self.calls.append((method, url))
        for frag, payload in self.routes.items():
            if frag in url:
                return _Resp(payload, self.status)
        raise AssertionError(f"unrouted: {method} {url}")


def test_five_plus_sources_registered():
    assert len(BUILTIN_SOURCES) >= 5, sorted(BUILTIN_SOURCES)
    assert {"shodan", "greynoise"} <= set(BUILTIN_SOURCES)


def test_shodan_flags_vulns_and_bad_tags():
    sess = _Sess(
        {
            "shodan.io": {
                "ports": [22, 445],
                "tags": ["malware"],
                "vulns": ["CVE-2021-1234", "CVE-2020-0001"],
            }
        }
    )
    v = ShodanSource(api_key="k", session=sess).enrich(IOC("1.2.3.4", IOCType.IP))
    assert v.error is None and v.malicious > 0.4
    assert any("malware" in l for l in v.labels)


def test_greynoise_malicious_classification():
    sess = _Sess({"greynoise.io": {"classification": "malicious", "noise": True, "name": "Mirai"}})
    v = GreyNoiseSource(api_key="k", session=sess).enrich(IOC("9.9.9.9", IOCType.IP))
    assert v.error is None and v.malicious >= 0.8
    assert "greynoise:malicious" in v.labels


def test_missing_key_is_graceful():
    v = ShodanSource(session=None).enrich(IOC("1.1.1.1", IOCType.IP))
    assert v.malicious == 0.0 and v.error == "missing api_key"


def test_misp_round_trip_preserves_indicators():
    enriched = [
        EnrichedIOC(ioc=IOC.parse("1.2.3.4"), score=0.9, severity="high", labels=["emotet"]),
        EnrichedIOC(ioc=IOC.parse("evil.test"), score=0.6, severity="medium", labels=["c2"]),
        EnrichedIOC(
            ioc=IOC.parse("44d88612fea8a8f36de82e1278abb02f"), score=0.3, severity="low", labels=[]
        ),
        EnrichedIOC(ioc=IOC.parse("http://evil.test/x"), score=0.8, severity="high", labels=[]),
    ]
    event = misp.build_event(enriched, info="test")
    assert event["Event"]["Attribute"], "no attributes built"
    parsed = misp.parse_event(event)
    src = {(e.ioc.value, e.ioc.type.value) for e in enriched}
    got = {(p["value"], p["type"]) for p in parsed}
    assert got == src, f"round-trip mismatch: {got ^ src}"
    # severity tag survives the round-trip
    assert any("severity" in l for p in parsed for l in p["labels"])


if __name__ == "__main__":
    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        globals()[name]()
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
