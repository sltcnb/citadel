"""Tests for Rosetta network enrichment (GeoIP/ASN/rDNS).

These exercise the PURE mapping logic with FAKE readers injected into the
:class:`Enricher` — no real MaxMind .mmdb files and no ``geoip2`` library are
required, so the suite runs anywhere.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rosetta.enrich import Enricher, _is_public_ip, enrich_event  # noqa: E402


# --- fake geoip2-shaped readers ------------------------------------------------


class _Country:
    def __init__(self, iso, name):
        self.iso_code = iso
        self.name = name


class _City:
    def __init__(self, name):
        self.name = name


class _Location:
    def __init__(self, lat, lon):
        self.latitude = lat
        self.longitude = lon


class _CityResp:
    def __init__(self):
        self.country = _Country("US", "United States")
        self.city = _City("Ashburn")
        self.location = _Location(39.0438, -77.4874)


class _AsnResp:
    def __init__(self):
        self.autonomous_system_number = 15169
        self.autonomous_system_organization = "GOOGLE"


class FakeCityReader:
    def __init__(self):
        self.calls = []

    def city(self, ip):
        self.calls.append(ip)
        return _CityResp()


class FakeAsnReader:
    def __init__(self):
        self.calls = []

    def asn(self, ip):
        self.calls.append(ip)
        return _AsnResp()


def _enricher():
    return Enricher(
        city_reader=FakeCityReader(),
        asn_reader=FakeAsnReader(),
        enable_rdns=False,
    )


# --- is_public_ip --------------------------------------------------------------


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_ips_recognized(ip):
    assert _is_public_ip(ip) is True


@pytest.mark.parametrize(
    "ip",
    ["10.0.0.5", "192.168.1.1", "172.16.4.4", "127.0.0.1", "::1", "169.254.0.1", "garbage"],
)
def test_private_and_invalid_ips_rejected(ip):
    assert _is_public_ip(ip) is False


# --- enrichment shape ----------------------------------------------------------


def test_public_ip_gets_geo_and_asn_in_ecs_shape():
    doc = {"source": {"ip": "8.8.8.8"}}
    enrich_event(doc, enricher=_enricher())

    geo = doc["source"]["geo"]
    assert geo["country_iso_code"] == "US"
    assert geo["country_name"] == "United States"
    assert geo["city_name"] == "Ashburn"
    assert geo["location"] == {"lat": 39.0438, "lon": -77.4874}

    asn = doc["source"]["as"]
    assert asn["number"] == 15169
    assert asn["organization_name"] == "GOOGLE"


def test_destination_field_enriched_too():
    doc = {"destination": {"ip": "1.1.1.1"}}
    enrich_event(doc, enricher=_enricher())
    assert doc["destination"]["geo"]["country_iso_code"] == "US"
    assert doc["destination"]["as"]["number"] == 15169


def test_all_ip_fields_covered():
    doc = {
        "source": {"ip": "8.8.8.8"},
        "destination": {"ip": "8.8.4.4"},
        "client": {"ip": "1.0.0.1"},
        "server": {"ip": "9.9.9.9"},
    }
    enrich_event(doc, enricher=_enricher())
    for f in ("source", "destination", "client", "server"):
        assert "geo" in doc[f]
        assert "as" in doc[f]


def test_private_ip_is_skipped():
    doc = {"source": {"ip": "10.0.0.1"}, "destination": {"ip": "192.168.1.5"}}
    enr = _enricher()
    enrich_event(doc, enricher=enr)
    assert "geo" not in doc["source"]
    assert "as" not in doc["source"]
    assert "geo" not in doc["destination"]
    # no lookups should have been attempted for private IPs
    assert enr.city_reader.calls == []
    assert enr.asn_reader.calls == []


def test_loopback_skipped():
    doc = {"source": {"ip": "127.0.0.1"}}
    enrich_event(doc, enricher=_enricher())
    assert "geo" not in doc["source"]


# --- graceful degradation ------------------------------------------------------


def test_missing_db_and_lib_is_noop():
    """Readers None + rDNS off => event returned unchanged (no-op)."""
    before = {"source": {"ip": "8.8.8.8"}}
    enr = Enricher(city_reader=None, asn_reader=None, enable_rdns=False)
    after = enrich_event({"source": {"ip": "8.8.8.8"}}, enricher=enr)
    assert after == before
    assert "geo" not in after["source"]
    assert "as" not in after["source"]


def test_reader_raising_does_not_crash():
    class Boom:
        def city(self, ip):
            raise RuntimeError("db corrupt")

        def asn(self, ip):
            raise RuntimeError("db corrupt")

    doc = {"source": {"ip": "8.8.8.8"}}
    enr = Enricher(city_reader=Boom(), asn_reader=Boom(), enable_rdns=False)
    # must not raise, and field stays bare
    enrich_event(doc, enricher=enr)
    assert "geo" not in doc["source"]
    assert "as" not in doc["source"]


def test_non_dict_event_returned_unchanged():
    assert enrich_event("not a dict", enricher=_enricher()) == "not a dict"


# --- no-overwrite --------------------------------------------------------------


def test_existing_geo_not_overwritten():
    doc = {"source": {"ip": "8.8.8.8", "geo": {"country_iso_code": "FR"}}}
    enrich_event(doc, enricher=_enricher())
    assert doc["source"]["geo"] == {"country_iso_code": "FR"}
    # as had no pre-existing value, so it should still be added
    assert doc["source"]["as"]["number"] == 15169


# --- rDNS opt-in ---------------------------------------------------------------


def test_rdns_off_by_default(monkeypatch):
    monkeypatch.delenv("ROSETTA_ENABLE_RDNS", raising=False)
    called = {"n": 0}

    def fake_gethostbyaddr(ip):
        called["n"] += 1
        return ("host.example.com", [], [ip])

    monkeypatch.setattr("rosetta.enrich.socket.gethostbyaddr", fake_gethostbyaddr)

    # enable_rdns left to env-resolution (None) -> env unset -> disabled
    enr = Enricher(city_reader=FakeCityReader(), asn_reader=FakeAsnReader())
    doc = {"source": {"ip": "8.8.8.8"}}
    enrich_event(doc, enricher=enr)
    assert "domain" not in doc["source"]
    assert called["n"] == 0


def test_rdns_enabled_attaches_domain_and_caches(monkeypatch):
    calls = []

    def fake_gethostbyaddr(ip):
        calls.append(ip)
        return ("dns.google", [], [ip])

    monkeypatch.setattr("rosetta.enrich.socket.gethostbyaddr", fake_gethostbyaddr)

    enr = Enricher(city_reader=None, asn_reader=None, enable_rdns=True)
    doc1 = {"source": {"ip": "8.8.8.8"}}
    doc2 = {"destination": {"ip": "8.8.8.8"}}
    enrich_event(doc1, enricher=enr)
    enrich_event(doc2, enricher=enr)
    assert doc1["source"]["domain"] == "dns.google"
    assert doc2["destination"]["domain"] == "dns.google"
    # cache => only one actual lookup for the repeated IP
    assert calls == ["8.8.8.8"]


def test_rdns_failure_swallowed(monkeypatch):
    def boom(ip):
        raise OSError("no PTR")

    monkeypatch.setattr("rosetta.enrich.socket.gethostbyaddr", boom)
    enr = Enricher(city_reader=None, asn_reader=None, enable_rdns=True)
    doc = {"source": {"ip": "8.8.8.8"}}
    enrich_event(doc, enricher=enr)  # must not raise
    assert "domain" not in doc["source"]


# --- integration with normalize -----------------------------------------------


def test_normalize_path_is_noop_without_dbs():
    """End-to-end: normalize_event must not crash and produces a doc even
    when no GeoIP DBs / geoip2 lib are present (default singleton no-ops)."""
    from rosetta.normalize import normalize_event

    event = {
        "timestamp": "2026-01-02T03:04:05Z",
        "artifact_type": "network",
        "raw": {"src_ip": "8.8.8.8", "dest_ip": "10.0.0.5", "proto": "tcp"},
    }
    doc = normalize_event(event)
    assert doc["source"]["ip"] == "8.8.8.8"
    # private dest never enriched; public src only enriched if DBs exist
    assert "geo" not in doc.get("destination", {})
