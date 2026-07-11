"""Property-based tests for pure normalizer/exporter helpers.

Uses Hypothesis (test-only dependency) to check invariants that value-based
example tests can miss:

* ``rosetta.normalize.to_iso_z`` — the timestamp canonicalization boundary the
  whole platform funnels through. Its output must always be a UTC 'Z' string
  and canonicalization must be idempotent.
* ``augur.stix.ioc_to_pattern`` — the STIX pattern it emits must round-trip
  back through the exact regex grammar the CTI router uses to parse it.

Skipped cleanly if Hypothesis is unavailable so the file never breaks a run
on a minimal interpreter.
"""

from __future__ import annotations

import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
for _p in (_ROOT / "tools" / "rosetta", _ROOT / "tools" / "augur"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from augur.models import IOC, IOCType  # noqa: E402
from augur.stix import ioc_to_pattern  # noqa: E402
from rosetta.normalize import to_iso_z  # noqa: E402

# Mirrors api/routers/cti.py _STIX_PATTERNS — the consumer of our STIX export.
_CTI_PATTERNS = [
    re.compile(r"\[file:hashes\.'[^']+'\s*=\s*'([^']+)'\]", re.IGNORECASE),
    re.compile(r"\[ipv[46]-addr:value\s*=\s*'([^']+)'\]", re.IGNORECASE),
    re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]", re.IGNORECASE),
    re.compile(r"\[url:value\s*=\s*'([^']+)'\]", re.IGNORECASE),
    re.compile(r"\[email-addr:value\s*=\s*'([^']+)'\]", re.IGNORECASE),
    re.compile(r"\[file:name\s*=\s*'([^']+)'\]", re.IGNORECASE),
]


def _cti_extract(pattern: str) -> str | None:
    for rx in _CTI_PATTERNS:
        m = rx.search(pattern)
        if m:
            return m.group(1)
    return None


# ── to_iso_z invariants ───────────────────────────────────────────────────────


@given(st.datetimes(timezones=st.just(UTC)))
def test_to_iso_z_always_utc_z_and_idempotent_for_datetimes(dt: datetime):
    out = to_iso_z(dt)
    assert isinstance(out, str)
    assert out.endswith("Z")
    assert "+" not in out  # never an explicit offset
    # Canonicalizing an already-canonical value is a no-op.
    assert to_iso_z(out) == out


@given(st.integers(min_value=0, max_value=4_000_000_000))
def test_to_iso_z_epoch_seconds_are_parseable_utc(epoch: int):
    out = to_iso_z(epoch)
    assert out.endswith("Z")
    # Round-trips back to the same instant (Z -> +00:00 for fromisoformat).
    parsed = datetime.fromisoformat(out.replace("Z", "+00:00"))
    assert int(parsed.timestamp()) == epoch


@given(st.sampled_from(["", None]))
def test_to_iso_z_empty_is_none(value):
    assert to_iso_z(value) is None


# ── ioc_to_pattern round-trip ─────────────────────────────────────────────────

# Value shapes that Augur classifies unambiguously into each type.
_ipv4 = st.builds(
    lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
    *([st.integers(min_value=0, max_value=255)] * 4),
)
_label = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=12)
_domain = st.builds(lambda a, b: f"{a}.{b}", _label, _label)
_sha256 = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)


@given(_ipv4)
def test_ip_pattern_roundtrips_through_cti_grammar(value):
    assert _cti_extract(ioc_to_pattern(IOC(value, IOCType.IP))) == value


@given(_domain)
def test_domain_pattern_roundtrips_through_cti_grammar(value):
    assert _cti_extract(ioc_to_pattern(IOC(value, IOCType.DOMAIN))) == value


@given(_sha256)
def test_hash_pattern_roundtrips_through_cti_grammar(value):
    assert _cti_extract(ioc_to_pattern(IOC(value, IOCType.HASH))) == value
