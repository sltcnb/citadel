"""Contract tests for the STIX 2.1 bundle Augur exports (consumed by the CTI
router and any external TIP that ingests it).

Asserts the *shape* of the exported objects — required keys, value types and
the STIX id/spec-version conventions — on a representative mix of indicator
types. Pure: no network, no live services.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_AUGUR = _ROOT / "tools" / "augur"
if str(_AUGUR) not in sys.path:
    sys.path.insert(0, str(_AUGUR))

from augur.models import IOC, EnrichedIOC, IOCType, SourceVerdict  # noqa: E402
from augur.scoring import score_enriched  # noqa: E402
from augur.stix import SPEC_VERSION, build_bundle  # noqa: E402


def _enriched(value: str, ioc_type: IOCType, malicious: float) -> EnrichedIOC:
    e = EnrichedIOC(ioc=IOC(value, ioc_type), verdicts=[SourceVerdict("urlhaus", malicious, 0.95)])
    return score_enriched(e, {"urlhaus": 1.0})


REPRESENTATIVE = [
    _enriched("1.2.3.4", IOCType.IP, 0.95),
    _enriched("evil.example", IOCType.DOMAIN, 0.8),
    _enriched("http://evil.example/x", IOCType.URL, 0.7),
    _enriched("a" * 64, IOCType.HASH, 0.9),
    _enriched("benign.example", IOCType.DOMAIN, 0.0),
]


def test_bundle_envelope_contract():
    bundle = build_bundle(REPRESENTATIVE)
    assert bundle["type"] == "bundle"
    assert isinstance(bundle["id"], str) and bundle["id"].startswith("bundle--")
    assert isinstance(bundle["objects"], list) and bundle["objects"]


def test_identity_and_indicator_object_contract():
    bundle = build_bundle(REPRESENTATIVE)
    identities = [o for o in bundle["objects"] if o["type"] == "identity"]
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]

    # Exactly one producing identity; one indicator per input IOC.
    assert len(identities) == 1
    assert len(indicators) == len(REPRESENTATIVE)
    identity = identities[0]
    assert identity["id"].startswith("identity--")

    for ind in indicators:
        # Required STIX indicator fields with correct types.
        assert ind["spec_version"] == SPEC_VERSION
        assert ind["id"].startswith("indicator--")
        assert isinstance(ind["pattern"], str) and ind["pattern"].startswith("[")
        assert ind["pattern_type"] == "stix"
        assert ind["created_by_ref"] == identity["id"]
        assert isinstance(ind["confidence"], int)
        assert 0 <= ind["confidence"] <= 100
        assert isinstance(ind["indicator_types"], list)
        # Augur custom scoring extension travels alongside the standard fields.
        assert isinstance(ind["x_augur_score"], (int, float))
        assert isinstance(ind["x_augur_severity"], str)
        # Timestamps are STIX-style UTC 'Z' strings.
        assert ind["created"].endswith("Z")
        assert ind["modified"].endswith("Z")


def test_malicious_indicator_carries_malicious_activity_label():
    bundle = build_bundle(REPRESENTATIVE)
    mal = next(
        o
        for o in bundle["objects"]
        if o["type"] == "indicator" and "1.2.3.4" in o["pattern"]
    )
    assert "malicious-activity" in mal["indicator_types"]
