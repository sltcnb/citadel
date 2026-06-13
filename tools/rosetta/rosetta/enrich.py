"""Network enrichment for normalized ECS events: GeoIP, ASN, reverse-DNS.

Adds analyst-friendly IP context (where / who / what-name) to the IP-bearing
ECS fields produced by :mod:`rosetta.normalize` (``source.ip``,
``destination.ip``, ``client.ip``, ``server.ip``). Output follows ECS shape:

    <field>.geo.{country_iso_code,country_name,city_name,location:{lat,lon}}
    <field>.as.{number,organization_name}
    <field>.domain                              (reverse-DNS PTR, opt-in)

Design goals:

* **Graceful degradation is mandatory.** If the ``geoip2`` library is not
  installed, or the ``.mmdb`` databases are absent, enrichment becomes a
  no-op: :func:`enrich_event` returns the event unchanged and never raises.
* **Cheap & lazy.** Readers are opened once on first use and cached on the
  module-level :class:`Enricher` singleton. Private/loopback/reserved IPs are
  skipped entirely (no lookup attempted).
* **Reverse-DNS is opt-in** (env ``ROSETTA_ENABLE_RDNS=true``) because it is
  slow and hits the network; results are cached and failures swallowed.
* **Injectable readers.** The :class:`Enricher` accepts ``city_reader`` /
  ``asn_reader`` so tests can exercise the pure mapping logic with fake
  readers and no real MaxMind DBs or library.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any

# ECS IP-bearing fields emitted by the normalizer. Each is a top-level object
# in the ECS doc carrying an ``ip`` key (e.g. doc["source"]["ip"]).
_IP_FIELDS = ("source", "destination", "client", "server")

_DEFAULT_CITY_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"
_DEFAULT_ASN_DB = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"

# Sentinel so we attempt lazy open exactly once and then cache the outcome
# (reader object or None) rather than re-trying on every event.
_UNSET = object()


def _truthy(val: str | None) -> bool:
    return (val or "").strip().lower() in ("1", "true", "yes", "on")


def _is_public_ip(ip: str) -> bool:
    """True only for globally-routable addresses worth enriching.

    Private (10/8, 172.16/12, 192.168/16), loopback (127/8, ::1), link-local,
    multicast, and otherwise-reserved addresses are skipped.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
    )


class Enricher:
    """Holds cached MaxMind readers + rDNS cache and applies ECS enrichment.

    Readers are resolved lazily and may be injected for testing. Any failure
    to load or query degrades to a no-op; this class never raises out of
    :meth:`enrich`.
    """

    def __init__(
        self,
        city_reader: Any = _UNSET,
        asn_reader: Any = _UNSET,
        enable_rdns: bool | None = None,
        rdns_timeout: float = 1.0,
    ):
        # _UNSET => resolve lazily from env on first use. Explicit value
        # (including None) => use as-is and skip lazy loading.
        self._city_reader = city_reader
        self._asn_reader = asn_reader
        self._enable_rdns = enable_rdns
        self._rdns_timeout = rdns_timeout
        self._rdns_cache: dict[str, str | None] = {}

    # -- reader resolution ----------------------------------------------------

    def _load_reader(self, env_var: str, default_path: str) -> Any:
        """Try to open a geoip2 Reader; return None on any failure (no-op)."""
        try:
            import geoip2.database  # noqa: PLC0415
        except Exception:
            return None
        path = os.environ.get(env_var, default_path)
        if not path or not os.path.exists(path):
            return None
        try:
            return geoip2.database.Reader(path)
        except Exception:
            return None

    @property
    def city_reader(self) -> Any:
        if self._city_reader is _UNSET:
            self._city_reader = self._load_reader("GEOIP_CITY_DB", _DEFAULT_CITY_DB)
        return self._city_reader

    @property
    def asn_reader(self) -> Any:
        if self._asn_reader is _UNSET:
            self._asn_reader = self._load_reader("GEOIP_ASN_DB", _DEFAULT_ASN_DB)
        return self._asn_reader

    @property
    def rdns_enabled(self) -> bool:
        if self._enable_rdns is None:
            self._enable_rdns = _truthy(os.environ.get("ROSETTA_ENABLE_RDNS"))
        return self._enable_rdns

    # -- per-IP lookups -------------------------------------------------------

    def _geo(self, ip: str) -> dict[str, Any] | None:
        reader = self.city_reader
        if reader is None:
            return None
        try:
            resp = reader.city(ip)
        except Exception:
            return None
        geo: dict[str, Any] = {}
        iso = getattr(resp.country, "iso_code", None)
        name = getattr(resp.country, "name", None)
        city = getattr(getattr(resp, "city", None), "name", None)
        loc = getattr(resp, "location", None)
        lat = getattr(loc, "latitude", None)
        lon = getattr(loc, "longitude", None)
        if iso:
            geo["country_iso_code"] = iso
        if name:
            geo["country_name"] = name
        if city:
            geo["city_name"] = city
        if lat is not None and lon is not None:
            geo["location"] = {"lat": lat, "lon": lon}
        return geo or None

    def _asn(self, ip: str) -> dict[str, Any] | None:
        reader = self.asn_reader
        if reader is None:
            return None
        try:
            resp = reader.asn(ip)
        except Exception:
            return None
        out: dict[str, Any] = {}
        num = getattr(resp, "autonomous_system_number", None)
        org = getattr(resp, "autonomous_system_organization", None)
        if num is not None:
            out["number"] = num
        if org:
            out["organization_name"] = org
        return out or None

    def _rdns(self, ip: str) -> str | None:
        if not self.rdns_enabled:
            return None
        if ip in self._rdns_cache:
            return self._rdns_cache[ip]
        result: str | None = None
        old = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self._rdns_timeout)
            result = socket.gethostbyaddr(ip)[0]
        except Exception:
            result = None
        finally:
            socket.setdefaulttimeout(old)
        self._rdns_cache[ip] = result
        return result

    # -- entry point ----------------------------------------------------------

    def enrich(self, event: dict[str, Any]) -> dict[str, Any]:
        """Enrich IP-bearing ECS fields in-place; return the event.

        No-op (event unchanged) when neither GeoIP DB nor rDNS is available.
        Never raises.
        """
        if not isinstance(event, dict):
            return event
        try:
            # Fast bail-out: if there is nothing to enrich with, do nothing.
            if self.city_reader is None and self.asn_reader is None and not self.rdns_enabled:
                return event
            for field in _IP_FIELDS:
                obj = event.get(field)
                if not isinstance(obj, dict):
                    continue
                ip = obj.get("ip")
                if not isinstance(ip, str) or not _is_public_ip(ip):
                    continue
                self._enrich_field(obj, ip)
        except Exception:
            # Belt-and-braces: enrichment must never break normalization.
            return event
        return event

    def _enrich_field(self, obj: dict[str, Any], ip: str) -> None:
        """Attach geo/as/domain to one ECS object, never overwriting existing."""
        if "geo" not in obj:
            geo = self._geo(ip)
            if geo:
                obj["geo"] = geo
        if "as" not in obj:
            asn = self._asn(ip)
            if asn:
                obj["as"] = asn
        if "domain" not in obj:
            ptr = self._rdns(ip)
            if ptr:
                obj["domain"] = ptr


# Module-level singleton: readers opened once, reused across all events.
_default_enricher = Enricher()


def enrich_event(event: dict[str, Any], enricher: Enricher | None = None) -> dict[str, Any]:
    """Enrich a normalized ECS event with GeoIP/ASN/rDNS context.

    Graceful no-op when geoip2 is missing or the .mmdb files are absent. Pass
    an explicit ``enricher`` (e.g. with injected fake readers) for testing.
    """
    return (enricher or _default_enricher).enrich(event)
