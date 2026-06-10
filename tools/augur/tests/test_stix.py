"""STIX 2.1 export shape tests + round-trip into CTI-style pattern regexes."""

from __future__ import annotations

import re

from augur.models import IOC, EnrichedIOC, IOCType, SourceVerdict
from augur.scoring import score_enriched
from augur.stix import SPEC_VERSION, build_bundle, ioc_to_pattern

# Mirrors api/routers/cti.py _STIX_PATTERNS (the consumer of our export).
_CTI_PATTERNS = [
    ("hash", re.compile(r"\[file:hashes\.'[^']+'\s*=\s*'([^']+)'\]", re.IGNORECASE)),
    ("ip", re.compile(r"\[ipv[46]-addr:value\s*=\s*'([^']+)'\]", re.IGNORECASE)),
    ("domain", re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]", re.IGNORECASE)),
    ("url", re.compile(r"\[url:value\s*=\s*'([^']+)'\]", re.IGNORECASE)),
    ("email", re.compile(r"\[email-addr:value\s*=\s*'([^']+)'\]", re.IGNORECASE)),
    ("filename", re.compile(r"\[file:name\s*=\s*'([^']+)'\]", re.IGNORECASE)),
]


def _match_any(pattern: str) -> str | None:
    for _t, rx in _CTI_PATTERNS:
        m = rx.search(pattern)
        if m:
            return m.group(1)
    return None


def test_patterns_match_cti_router_grammar():
    cases = [
        (IOC("1.2.3.4", IOCType.IP), "1.2.3.4"),
        (IOC("evil.com", IOCType.DOMAIN), "evil.com"),
        (IOC("http://evil.com/x", IOCType.URL), "http://evil.com/x"),
        (IOC("a@b.com", IOCType.EMAIL), "a@b.com"),
        (IOC("dropper.exe", IOCType.FILENAME), "dropper.exe"),
        (IOC("a" * 64, IOCType.HASH), "a" * 64),
    ]
    for ioc, value in cases:
        pat = ioc_to_pattern(ioc)
        assert _match_any(pat) == value, pat


def _enriched(ioc, mal):
    e = EnrichedIOC(ioc=ioc, verdicts=[SourceVerdict("urlhaus", mal, 0.95)])
    return score_enriched(e, {"urlhaus": 1.0})


def test_bundle_shape():
    enriched = [
        _enriched(IOC("1.2.3.4", IOCType.IP), 0.95),
        _enriched(IOC("benign.com", IOCType.DOMAIN), 0.0),
    ]
    bundle = build_bundle(enriched)

    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")

    identities = [o for o in bundle["objects"] if o["type"] == "identity"]
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(identities) == 1
    assert len(indicators) == 2

    for ind in indicators:
        assert ind["spec_version"] == SPEC_VERSION
        assert ind["id"].startswith("indicator--")
        assert ind["pattern_type"] == "stix"
        assert ind["created_by_ref"] == identities[0]["id"]
        assert 0 <= ind["confidence"] <= 100
        assert "x_augur_score" in ind and "x_augur_severity" in ind

    mal_ind = next(i for i in indicators if "1.2.3.4" in i["pattern"])
    assert "malicious-activity" in mal_ind["indicator_types"]


def test_indicator_id_is_deterministic():
    a = build_bundle([_enriched(IOC("1.2.3.4", IOCType.IP), 0.9)])
    b = build_bundle([_enriched(IOC("1.2.3.4", IOCType.IP), 0.9)])
    ai = next(o for o in a["objects"] if o["type"] == "indicator")["id"]
    bi = next(o for o in b["objects"] if o["type"] == "indicator")["id"]
    assert ai == bi
