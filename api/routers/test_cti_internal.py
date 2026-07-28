"""Internal infrastructure must never be reported as a threat-intel match.

An IOC's stored ``is_private`` flag is only as good as the code that wrote it —
feeds ingested before the flag existed carry nothing — which is how 10.x /
192.168.x addresses came back as HIGH "CTI match" detections for every internal
host in a case. Classification is therefore derived from the value itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import routers.cti as cti  # noqa: E402

INTERNAL_IPS = [
    "10.0.0.9",
    "10.255.255.255",
    "172.16.4.1",
    "172.31.0.7",
    "192.168.1.1",
    "127.0.0.1",
    "169.254.169.254",  # cloud metadata
    "100.64.0.1",  # CGNAT
    "0.0.0.0",
    "224.0.0.1",  # multicast
    "240.0.0.1",  # reserved
    "::1",
    "fe80::1",
    "fd00::abcd",
]

EXTERNAL_IPS = [
    "8.8.8.8",
    "1.1.1.1",
    "213.36.7.14",
    "172.32.0.1",  # just outside 172.16/12
    "100.128.0.1",  # just outside CGNAT
    "45.33.32.156",
    "2606:4700::1111",
]


@pytest.mark.parametrize("value", INTERNAL_IPS)
def test_internal_ips_are_flagged(value):
    assert cti._is_internal_ioc("ip", value) is True
    assert cti._ip_is_private(value) is True


@pytest.mark.parametrize("value", EXTERNAL_IPS)
def test_routable_ips_are_not_flagged(value):
    assert cti._is_internal_ioc("ip", value) is False
    assert cti._ip_is_private(value) is False


@pytest.mark.parametrize(
    "value", ["localhost", "dc01.corp", "printer.local", "svc.internal", "box.lan", "HOST.LAN"]
)
def test_internal_hostnames_are_flagged(value):
    assert cti._is_internal_ioc("domain", value) is True


@pytest.mark.parametrize("value", ["evil.com", "cdn.example.org", "a.b.co.uk"])
def test_public_domains_are_not_flagged(value):
    assert cti._is_internal_ioc("domain", value) is False


@pytest.mark.parametrize("ioc_type", ["hash", "url", "email", "filename"])
def test_other_types_are_never_classified_by_value(ioc_type):
    """Only IPs and domains name infrastructure; a URL containing 10.0.0.1 is
    still a URL IOC and must not be silently downgraded."""
    assert cti._is_internal_ioc(ioc_type, "http://10.0.0.1/payload") is False


@pytest.mark.parametrize("value", ["", "   ", "not-an-ip", "999.999.999.999", None])
def test_malformed_values_do_not_raise(value):
    assert cti._is_internal_ioc("ip", value) is False
