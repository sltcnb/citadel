"""
Cyber Threat Intelligence (CTI) Integration.

Manages STIX/TAXII feed subscriptions, manual STIX bundle imports, and IOC
matching against case data. Supports STIX 2.1 indicators (hashes, IPs, domains,
URLs, email addresses, file names).

IOCs are stored in Redis and automatically matched when alert rules or modules run.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import redis as redis_lib
import redis_keys as rk
from auth.dependencies import require_case_access
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from services.elasticsearch import _request as es_req
from services.redis_mutate import mutate_json

from config import get_redis as _redis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["cti"])


# ── URL validation (SSRF prevention) ────────────────────────────────────────

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Feed pagination — pull every page, not just the first 10k.
_FEED_PAGE_SIZE = 10000        # records per request
_FEED_MAX_TOTAL = 2_000_000    # hard safety ceiling per pull


def _validate_feed_url(url: str) -> None:
    """Block SSRF: refuse non-http(s), localhost/.local, and any hostname that
    RESOLVES to a private/reserved/loopback/link-local address (not just literal
    IPs). Defeats internal-service / cloud-metadata (169.254.169.254) targeting."""
    import socket

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400, detail=f"Feed URL must use http or https, got '{parsed.scheme}'"
        )
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname or hostname in ("localhost",) or hostname.endswith(".local") or hostname.endswith(".internal"):
        raise HTTPException(status_code=400, detail="Feed URL host is not allowed")
    # Resolve every address the host maps to and reject if ANY is non-public.
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError:
        raise HTTPException(status_code=400, detail=f"Feed URL host does not resolve: {hostname}")
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            raise HTTPException(
                status_code=400,
                detail="Feed URL must not resolve to a private/reserved/internal address",
            )


def _safe_urlopen(req, timeout: int, verify: bool = True):
    """urlopen that re-validates every redirect target against _validate_feed_url.

    The initial URL is validated by callers, but urllib follows 3xx redirects by
    default — a validated public host could 302 us to 169.254.169.254 or an
    internal service. Re-checking each hop closes that bypass. (Residual: a
    DNS-rebinding TOCTOU between validation and connect is not addressed here.)

    `verify=False` disables TLS certificate verification — for an internal
    TAXII/STIX server with a self-signed cert the operator trusts."""
    import ssl
    import urllib.request

    class _ValidatingRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            _validate_feed_url(newurl)
            return super().redirect_request(request, fp, code, msg, headers, newurl)

    handlers = [_ValidatingRedirect()]
    if not verify:
        handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    opener = urllib.request.build_opener(*handlers)
    return opener.open(req, timeout=timeout)


# ── Redis key layout ─────────────────────────────────────────────────────────
# fo:cti:feeds                → JSON list of feed configs
# fo:cti:iocs:type:{type}     → Redis SET of JSON IOC objects per type
# fo:cti:iocs:hash:{value}    → indicator detail for fast hash lookups
# fo:cti:iocs:detail:{id}     → full indicator JSON by indicator ID

FEEDS_KEY = rk.CTI_FEEDS

IOC_TYPES = ("hash", "ip", "domain", "url", "email", "filename")


# ── Pydantic models ──────────────────────────────────────────────────────────


class FeedCreate(BaseModel):
    name: str
    type: str  # "taxii" | "stix_url" | "manual"
    url: str = ""
    api_key: str = ""
    collection: str = ""
    poll_interval_value: int = 24
    poll_interval_unit: str = "hours"  # "minutes" | "hours" | "days"
    auto_pull: bool = True
    # Verify the feed server's TLS certificate. Default True; set False only for
    # an internal MISP/TAXII with a self-signed cert you trust.
    verify_ssl: bool = True


class FeedUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    api_key: str | None = None
    collection: str | None = None
    poll_interval_value: int | None = None
    poll_interval_unit: str | None = None
    auto_pull: bool | None = None
    enabled: bool | None = None
    verify_ssl: bool | None = None


class BundleImport(BaseModel):
    bundle: dict


# ── Feed helpers ─────────────────────────────────────────────────────────────


def _load_feeds(r: redis_lib.Redis) -> list[dict]:
    raw = r.get(FEEDS_KEY)
    return json.loads(raw) if raw else []


def _save_feeds(r: redis_lib.Redis, feeds: list[dict]) -> None:
    r.set(FEEDS_KEY, json.dumps(feeds))


def _find_feed(feeds: list[dict], feed_id: str) -> dict | None:
    return next((f for f in feeds if f["id"] == feed_id), None)


# ── Scheduler helpers ────────────────────────────────────────────────────────


def _feed_interval_seconds(feed: dict) -> int:
    """Return the polling interval in seconds for a feed, with backward compat."""
    val = int(feed.get("poll_interval_value") or feed.get("poll_interval_hours") or 24)
    unit = feed.get("poll_interval_unit", "hours")
    mult = {"minutes": 60, "hours": 3600, "days": 86400}.get(unit, 3600)
    return max(60, val * mult)  # never less than 1 minute


def _pull_feed_now(feed: dict, r: redis_lib.Redis, feeds: list[dict]) -> int:
    """Internal (non-HTTP) version of pull_feed. Returns ioc_count on success."""
    feed_type = feed.get("type", "")
    # Manual feeds with a URL can be auto-re-imported as stix_url
    effective_type = feed_type
    if feed_type == "manual":
        if feed.get("url", "").strip():
            effective_type = "stix_url"
        else:
            return 0  # pure manual feed — nothing to auto-pull
    from citadel_contracts.logship import tool_logger
    aug = tool_logger("augur", r)
    aug.info("[Augur] auto-pull: downloading feed '%s' (%s)…", feed.get("name", "?"), effective_type)
    try:
        # Fetch first; replace only on success so a failure can't wipe IOCs.
        if effective_type == "taxii":
            data = _taxii_fetch(feed)
            _remove_feed_iocs(r, feed["id"])
            count = _process_stix_bundle(r, data, feed_id=feed["id"], feed_name=feed["name"])
        elif effective_type == "stix_url":
            data = _stix_url_fetch(feed)
            _remove_feed_iocs(r, feed["id"])
            count = _process_stix_bundle(r, data, feed_id=feed["id"], feed_name=feed["name"])
        elif effective_type == "misp":
            attrs = _misp_fetch(feed)
            _remove_feed_iocs(r, feed["id"])
            count = _process_misp_attributes(r, attrs, feed_id=feed["id"], feed_name=feed["name"])
        elif effective_type == "yeti":
            observables = _yeti_fetch(feed)
            _remove_feed_iocs(r, feed["id"])
            count = _process_yeti_observables(
                r, observables, feed_id=feed["id"], feed_name=feed["name"]
            )
        else:
            return 0
        feed["last_pull"] = datetime.now(UTC).isoformat()
        feed["ioc_count"] = count
        _save_feeds(r, feeds)
        aug.info("[Augur] feed '%s' downloaded: %d IOC(s) (deduped)", feed.get("name", "?"), count)
        return count
    except Exception as exc:
        aug.error("[Augur] auto-pull FAILED for feed '%s': %s", feed.get("name", "?"), exc)
        return 0


async def start_cti_scheduler() -> None:
    """
    Background coroutine — started at API startup.
    Wakes every 60 s and auto-pulls feeds whose interval has elapsed.
    """
    logger.info("CTI scheduler started")
    _ticks = 0
    while True:
        await asyncio.sleep(60)
        try:
            r = _redis()
            # Purge expired IOCs roughly hourly (every 60 ticks).
            _ticks += 1
            if _ticks % 60 == 0:
                try:
                    n = _purge_expired_iocs(r)
                    if n:
                        logger.info("CTI scheduler purged %d expired IOC(s)", n)
                except Exception as exc:
                    logger.warning("CTI expired-purge error: %s", exc)
            feeds = _load_feeds(r)
            now = datetime.now(UTC)
            for feed in feeds:
                if not feed.get("enabled", True):
                    continue
                if not feed.get("auto_pull", True):
                    continue
                # Skip pure manual feeds (no URL) — they have no source to pull from
                if feed.get("type") == "manual" and not feed.get("url", "").strip():
                    continue
                interval_sec = _feed_interval_seconds(feed)
                last_pull = feed.get("last_pull")
                if last_pull:
                    try:
                        elapsed = (now - datetime.fromisoformat(last_pull)).total_seconds()
                        if elapsed < interval_sec:
                            continue
                    except ValueError:
                        pass  # malformed timestamp — pull anyway
                logger.info("CTI auto-pull: feed %s (%s)", feed["id"], feed.get("name", "?"))
                # Reload feeds inside loop so parallel saves are captured
                feeds_fresh = _load_feeds(r)
                feed_fresh = _find_feed(feeds_fresh, feed["id"])
                if feed_fresh:
                    # _pull_feed_now does blocking network I/O (urlopen, up to 60s
                    # per request) + Redis writes — running it inline would stall
                    # the event loop and every API request with it. Offload to a
                    # worker thread.
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, _pull_feed_now, feed_fresh, r, feeds_fresh)
        except Exception as exc:
            logger.warning("CTI scheduler tick error: %s", exc)


# ── STIX pattern parser ─────────────────────────────────────────────────────

# Regex patterns for common STIX 2.1 indicator patterns
_STIX_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("hash", re.compile(r"\[file:hashes\.\w+\s*=\s*'([^']+)'\]", re.IGNORECASE)),
    ("hash", re.compile(r"\[file:hashes\.'[^']+'\s*=\s*'([^']+)'\]", re.IGNORECASE)),
    ("ip", re.compile(r"\[ipv[46]-addr:value\s*=\s*'([^']+)'\]", re.IGNORECASE)),
    ("domain", re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]", re.IGNORECASE)),
    ("url", re.compile(r"\[url:value\s*=\s*'([^']+)'\]", re.IGNORECASE)),
    ("email", re.compile(r"\[email-addr:value\s*=\s*'([^']+)'\]", re.IGNORECASE)),
    ("filename", re.compile(r"\[file:name\s*=\s*'([^']+)'\]", re.IGNORECASE)),
]


def _parse_stix_pattern(pattern: str) -> list[tuple[str, str]]:
    """
    Extract (ioc_type, value) pairs from a STIX indicator pattern string.

    Uses simple regex matching rather than a full STIX pattern evaluator.
    Returns an empty list if no known pattern is matched.
    """
    results: list[tuple[str, str]] = []
    for ioc_type, regex in _STIX_PATTERNS:
        for match in regex.finditer(pattern):
            value = match.group(1).strip()
            if value:
                results.append((ioc_type, value))
    return results


# ── IOC storage helpers ──────────────────────────────────────────────────────


_DEFAULT_IOC_TTL_DAYS = 90


def _ioc_dedup_key(ioc_type: str, value: str) -> str:
    """Identity used for dedup — same value (case-insensitive except URLs)
    collapses to one IOC regardless of feed or pull time."""
    return value if ioc_type == "url" else value.lower()


# Storage moved from a SET (per-type, JSON members) to a HASH (value→JSON) for
# real dedup. Old deployments left SET-typed keys; the first touch of each key
# after upgrade drops the stale SET so HASH ops don't WRONGTYPE. Re-pull
# repopulates (deduped). Cached so it's one type-check per key per process.
_IOC_KEY_MIGRATED: set = set()


def _ensure_ioc_hash(r: redis_lib.Redis, type_key: str) -> None:
    if type_key in _IOC_KEY_MIGRATED:
        return
    try:
        t = r.type(type_key)
        t = t.decode() if isinstance(t, bytes) else t
        if t not in ("hash", "none"):
            r.delete(type_key)  # stale SET (or other) — drop; re-pull repopulates
            logger.warning("Migrated stale IOC key %s (%s → hash)", type_key, t)
    except Exception:  # noqa: BLE001
        pass
    _IOC_KEY_MIGRATED.add(type_key)


def _ip_is_private(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("/")[0])
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETWORKS)


# Operator-defined "own" public networks — their org's egress/hosting IPs. IOCs
# or events matching these are flagged is_own so they can be filtered out of
# threat matches (your own infrastructure isn't an indicator).
_OWN_NETWORKS_KEY = "cti:own_networks"
_OWN_NETS_CACHE: list | None = None


def _own_networks(r: redis_lib.Redis) -> list:
    global _OWN_NETS_CACHE
    if _OWN_NETS_CACHE is not None:
        return _OWN_NETS_CACHE
    nets = []
    raw = r.get(_OWN_NETWORKS_KEY)
    if raw:
        try:
            for c in json.loads(raw):
                try:
                    nets.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    continue
        except (json.JSONDecodeError, TypeError):
            pass
    _OWN_NETS_CACHE = nets
    return nets


def _ip_is_own(value: str, r: redis_lib.Redis) -> bool:
    nets = _own_networks(r)
    if not nets:
        return False
    try:
        ip = ipaddress.ip_address(value.split("/")[0])
    except ValueError:
        return False
    return any(ip in net for net in nets)


def _ioc_expired(obj: dict) -> bool:
    vu = obj.get("valid_until")
    if not vu:
        return False
    try:
        return datetime.fromisoformat(str(vu)) < datetime.now(UTC)
    except ValueError:
        return False


def _store_ioc(
    r: redis_lib.Redis,
    ioc_type: str,
    value: str,
    indicator_id: str = "",
    feed_id: str = "",
    feed_name: str = "",
    indicator_name: str = "",
    created: str = "",
    valid_until: str = "",
    confidence: int | None = None,
    threat_type: str = "",
    tags: list | None = None,
) -> None:
    """Store/merge a single IOC in Redis, deduplicated by value.

    Stored in a per-type HASH keyed by the dedup value, so re-pulling or a
    second feed updates one entry instead of duplicating. Merges feeds/tags,
    keeps the earliest first_seen, refreshes last_seen, and fills available
    fields (confidence, threat_type, validity, private-IP flag)."""
    type_key = rk.cti_ioc_type(ioc_type)
    _ensure_ioc_hash(r, type_key)
    dedup = _ioc_dedup_key(ioc_type, value)
    now = datetime.now(UTC).isoformat()

    existing: dict = {}
    prev = r.hget(type_key, dedup)
    if prev:
        try:
            existing = json.loads(prev)
        except (json.JSONDecodeError, TypeError):
            existing = {}

    merged_tags = sorted(set((tags or []) + (existing.get("tags") or [])))
    if not valid_until and not existing.get("valid_until"):
        valid_until = (datetime.now(UTC) + timedelta(days=_DEFAULT_IOC_TTL_DAYS)).isoformat()

    ioc_obj = {
        "type": ioc_type,
        "value": value if ioc_type == "url" else value.lower(),
        "indicator_id": indicator_id or existing.get("indicator_id", ""),
        "feed_id": feed_id or existing.get("feed_id", ""),
        "feed_name": feed_name or existing.get("feed_name", ""),
        "indicator_name": indicator_name or existing.get("indicator_name", ""),
        "created": existing.get("created") or created or now,
        "first_seen": existing.get("first_seen") or created or now,
        "last_seen": now,
        "valid_until": valid_until or existing.get("valid_until", ""),
        "confidence": confidence if confidence is not None else existing.get("confidence"),
        "threat_type": threat_type or existing.get("threat_type", ""),
        "tags": merged_tags,
    }
    if ioc_type == "ip":
        ioc_obj["is_private"] = _ip_is_private(value)
        ioc_obj["is_own"] = _ip_is_own(value, r)
    ioc_json = json.dumps(ioc_obj, sort_keys=True)

    # Per-type HASH keyed by value → natural dedup.
    r.hset(type_key, dedup, ioc_json)

    if ioc_type == "hash":
        r.set(rk.cti_ioc_hash(value.lower()), ioc_json)
    if indicator_id:
        r.set(rk.cti_ioc_detail(indicator_id), ioc_json)


def _process_stix_bundle(
    r: redis_lib.Redis,
    bundle: dict,
    feed_id: str = "",
    feed_name: str = "",
) -> int:
    """
    Parse a STIX 2.1 bundle, extract indicators, and store IOCs.
    Returns the number of IOCs stored.
    """
    objects = bundle.get("objects", [])
    count = 0

    for obj in objects:
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        indicator_id = obj.get("id", "")
        indicator_name = obj.get("name", "")
        created = obj.get("created", "")

        extracted = _parse_stix_pattern(pattern)
        for ioc_type, value in extracted:
            _store_ioc(
                r,
                ioc_type=ioc_type,
                value=value,
                indicator_id=indicator_id,
                feed_id=feed_id,
                feed_name=feed_name,
                indicator_name=indicator_name,
                created=created,
            )
            count += 1

    return count


def _count_feed_iocs(r: redis_lib.Redis, feed_id: str) -> int:
    """Count total IOCs belonging to a specific feed across all type hashes."""
    total = 0
    for ioc_type in IOC_TYPES:
        type_key = rk.cti_ioc_type(ioc_type)
        _ensure_ioc_hash(r, type_key)
        for m in r.hvals(type_key):
            try:
                if json.loads(m).get("feed_id") == feed_id:
                    total += 1
            except (json.JSONDecodeError, TypeError):
                pass
    return total


def _remove_feed_iocs(r: redis_lib.Redis, feed_id: str) -> int:
    """Remove all IOCs belonging to a specific feed. Returns count removed."""
    removed = 0
    for ioc_type in IOC_TYPES:
        type_key = rk.cti_ioc_type(ioc_type)
        _ensure_ioc_hash(r, type_key)
        to_remove = []
        for field, m in r.hgetall(type_key).items():
            try:
                obj = json.loads(m)
                if obj.get("feed_id") == feed_id:
                    to_remove.append(field)
                    if obj.get("indicator_id"):
                        r.delete(rk.cti_ioc_detail(obj["indicator_id"]))
                    if ioc_type == "hash":
                        r.delete(rk.cti_ioc_hash(obj["value"]))
            except (json.JSONDecodeError, TypeError):
                pass
        if to_remove:
            r.hdel(type_key, *to_remove)
            removed += len(to_remove)
    return removed


# ── TAXII 2.1 client helpers ────────────────────────────────────────────────


def _taxii_fetch(feed: dict) -> dict:
    """
    Fetch STIX objects from a TAXII 2.1 collection endpoint.

    Implements the minimum viable TAXII 2.1 client:
      GET {url}/collections/{collection}/objects/
      Accept: application/taxii+json;version=2.1

    Returns a STIX bundle dict.
    """
    import urllib.error
    import urllib.request

    _validate_feed_url(feed["url"])
    base_url = feed["url"].rstrip("/")
    collection = feed.get("collection", "")

    if collection:
        objects_url = f"{base_url}/collections/{collection}/objects/"
    else:
        objects_url = f"{base_url}/objects/"

    headers = {
        "Accept": "application/taxii+json;version=2.1",
        "Content-Type": "application/taxii+json;version=2.1",
    }
    if feed.get("api_key"):
        headers["Authorization"] = f"Bearer {feed['api_key']}"

    req = urllib.request.Request(objects_url, headers=headers, method="GET")
    try:
        with _safe_urlopen(req, 60, verify=feed.get("verify_ssl", True)) as resp:
            data = json.loads(resp.read())
            # TAXII 2.1 envelope has "objects" at top level
            if "objects" in data:
                return {"type": "bundle", "objects": data["objects"]}
            return data
    except urllib.error.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"TAXII server returned HTTP {exc.code}: {exc.reason}",
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"TAXII fetch failed: {exc}")


def _stix_url_fetch(feed: dict) -> dict:
    """
    Fetch a STIX bundle JSON from a plain URL.
    """
    import urllib.error
    import urllib.request

    _validate_feed_url(feed["url"])
    url = feed["url"]
    headers: dict[str, str] = {"Accept": "application/json"}
    if feed.get("api_key"):
        headers["Authorization"] = f"Bearer {feed['api_key']}"

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _safe_urlopen(req, 60, verify=feed.get("verify_ssl", True)) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"STIX URL returned HTTP {exc.code}: {exc.reason}",
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"STIX URL fetch failed: {exc}")


# ── MISP integration ─────────────────────────────────────────────────────────

_MISP_TYPE_MAP: dict[str, str] = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "ip-src|port": "ip",
    "ip-dst|port": "ip",
    "domain": "domain",
    "hostname": "domain",
    "domain|ip": "domain",
    "url": "url",
    "uri": "url",
    "email": "email",
    "email-src": "email",
    "email-dst": "email",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "sha512": "hash",
    "ssdeep": "hash",
    "tlsh": "hash",
    "filename": "filename",
    "filename|md5": "filename",
    "filename|sha1": "filename",
    "filename|sha256": "filename",
}


def _misp_fetch(feed: dict) -> list:
    """Fetch indicator attributes from a MISP instance."""
    try:
        import requests as _req  # type: ignore
    except ImportError:
        raise HTTPException(status_code=500, detail="'requests' package not installed")
    base_url = feed.get("url", "").rstrip("/")
    _validate_feed_url(base_url)  # SSRF guard
    api_key = feed.get("api_key", "")
    headers: dict[str, str] = {
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    collection = feed.get("collection", "").strip()
    per_page = int(feed.get("page_size", 0) or _FEED_PAGE_SIZE)
    all_attrs: list = []
    page = 1
    try:
        while len(all_attrs) < _FEED_MAX_TOTAL:
            payload: dict[str, Any] = {
                "returnFormat": "json", "limit": per_page, "page": page,
            }
            # Only restrict to IDS-flagged attributes if the feed asks for it —
            # otherwise pull ALL attributes (a MISP attribute without the to_ids
            # flag was being dropped, so two IPs showed up as one).
            if feed.get("to_ids_only"):
                payload["to_ids"] = 1
            if collection:
                payload["tags"] = [collection]
            resp = _req.post(
                f"{base_url}/attributes/restSearch",
                json=payload, headers=headers, timeout=120,
                allow_redirects=False,  # SSRF: don't follow a redirect off the validated host
                verify=feed.get("verify_ssl", True),
            )
            resp.raise_for_status()
            attrs = resp.json().get("response", {}).get("Attribute", [])
            if not isinstance(attrs, list) or not attrs:
                break
            all_attrs.extend(attrs)
            if len(attrs) < per_page:
                break  # last page
            page += 1
        return all_attrs
    except HTTPException:
        raise
    except Exception as exc:
        # Return what we have rather than losing a large partial pull.
        if all_attrs:
            logger.warning("MISP fetch stopped at page %d (%d attrs): %s", page, len(all_attrs), exc)
            return all_attrs
        raise HTTPException(status_code=502, detail=f"MISP fetch failed: {exc}")


def _process_misp_attributes(
    r: redis_lib.Redis, attributes: list, feed_id: str, feed_name: str
) -> int:
    """Store MISP attributes as IOCs. Returns count."""
    count = 0
    for attr in attributes:
        attr_type = attr.get("type", "")
        raw_value = attr.get("value", "").strip()
        if not raw_value:
            continue
        ioc_type = _MISP_TYPE_MAP.get(attr_type, "")
        if not ioc_type:
            continue
        value = raw_value.split("|")[0].strip() if "|" in attr_type else raw_value
        ts = attr.get("timestamp", "")
        created = ""
        if ts:
            try:
                created = datetime.fromtimestamp(int(ts), tz=UTC).isoformat()
            except (ValueError, TypeError):
                created = str(ts)
        tag_names = [t.get("name", "") for t in (attr.get("Tag") or []) if t.get("name")]
        _store_ioc(
            r,
            ioc_type,
            value,
            indicator_id=attr.get("uuid", ""),
            feed_id=feed_id,
            feed_name=feed_name,
            indicator_name=attr.get("comment", ""),
            created=created,
            threat_type=attr.get("category", ""),
            tags=tag_names,
        )
        count += 1
    return count


# ── YETI integration ──────────────────────────────────────────────────────────

_YETI_TYPE_MAP: dict[str, str] = {
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ip",
    "cidr": "ip",
    "hostname": "domain",
    "fqdn": "domain",
    "domain": "domain",
    "url": "url",
    "email": "email",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "sha512": "hash",
    "hash": "hash",
    "file": "hash",
    "filename": "filename",
    # YETI v1 class names
    "IPv4": "ip",
    "IPv6": "ip",
    "Hostname": "domain",
    "URL": "url",
    "Email": "email",
    "MD5": "hash",
    "SHA256": "hash",
}


def _yeti_fetch(feed: dict) -> list:
    """Fetch observables from a YETI v2 instance."""
    try:
        import requests as _req  # type: ignore
    except ImportError:
        raise HTTPException(status_code=500, detail="'requests' package not installed")
    base_url = feed.get("url", "").rstrip("/")
    _validate_feed_url(base_url)  # SSRF guard
    api_key = feed.get("api_key", "")
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    per_page = int(feed.get("page_size", 0) or _FEED_PAGE_SIZE)
    all_obs: list = []
    page = 0
    try:
        while len(all_obs) < _FEED_MAX_TOTAL:
            resp = _req.post(
                f"{base_url}/api/v2/observables/search",
                json={"query": {"name": ""}, "type": "all", "count": per_page, "page": page},
                headers=headers, timeout=120,
                allow_redirects=False,  # SSRF: don't follow a redirect off the validated host
                verify=feed.get("verify_ssl", True),
            )
            resp.raise_for_status()
            data = resp.json()
            batch = data if isinstance(data, list) else data.get("observables", data.get("data", []))
            if not batch:
                break
            all_obs.extend(batch)
            if len(batch) < per_page:
                break
            page += 1
        return all_obs
    except HTTPException:
        raise
    except Exception as exc:
        if all_obs:
            logger.warning("YETI fetch stopped at page %d (%d obs): %s", page, len(all_obs), exc)
            return all_obs
        raise HTTPException(status_code=502, detail=f"YETI fetch failed: {exc}")


def _process_yeti_observables(
    r: redis_lib.Redis, observables: list, feed_id: str, feed_name: str
) -> int:
    """Store YETI observables as IOCs. Returns count."""
    count = 0
    for obs in observables:
        obs_type = obs.get("type", obs.get("__type__", ""))
        obs_value = obs.get("value", obs.get("name", "")).strip()
        if not obs_value:
            continue
        ioc_type = _YETI_TYPE_MAP.get(obs_type, "")
        if not ioc_type:
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}", obs_value):
                ioc_type = "ip"
            elif re.match(r"^https?://", obs_value):
                ioc_type = "url"
            elif re.match(r"^[a-fA-F0-9]{32,64}$", obs_value):
                ioc_type = "hash"
            else:
                continue
        tags = obs.get("tags", [])
        label = obs.get("description", tags[0] if tags else "")
        _store_ioc(
            r,
            ioc_type,
            obs_value,
            indicator_id=str(obs.get("id", "")),
            feed_id=feed_id,
            feed_name=feed_name,
            indicator_name=label,
            created=obs.get("created_at", obs.get("created", "")),
        )
        count += 1
    return count


# ── Feed endpoints ───────────────────────────────────────────────────────────


@router.get("/cti/feeds")
def list_feeds():
    """List all configured CTI feeds (api_key redacted — never returned raw)."""
    r = _redis()
    feeds = _load_feeds(r)
    # Redact secrets in the response only; the stored feed records keep their keys.
    redacted = []
    for feed in feeds:
        f = dict(feed)
        if "api_key" in f:
            f["api_key_set"] = bool(f.pop("api_key"))
        redacted.append(f)
    return {"feeds": redacted}


@router.post("/cti/feeds", status_code=201)
def add_feed(body: FeedCreate):
    """Add a new CTI feed configuration."""
    if body.type not in ("taxii", "stix_url", "manual", "misp", "yeti"):
        raise HTTPException(
            status_code=422,
            detail="Feed type must be 'taxii', 'stix_url', 'manual', 'misp', or 'yeti'.",
        )
    if body.type != "manual" and not body.url:
        raise HTTPException(status_code=422, detail="URL is required for non-manual feeds.")

    if body.poll_interval_unit not in ("minutes", "hours", "days"):
        raise HTTPException(
            status_code=422, detail="poll_interval_unit must be 'minutes', 'hours', or 'days'."
        )
    r = _redis()
    feed = {
        "id": str(uuid.uuid4())[:8],
        "name": body.name,
        "type": body.type,
        "url": body.url,
        "api_key": body.api_key,
        "collection": body.collection,
        "poll_interval_value": body.poll_interval_value,
        "poll_interval_unit": body.poll_interval_unit,
        "auto_pull": body.auto_pull,
        "enabled": True,
        "last_pull": None,
        "ioc_count": 0,
        "created_at": datetime.now(UTC).isoformat(),
    }
    mutate_json(r, FEEDS_KEY, lambda feeds: feeds + [feed], [])
    return feed


@router.put("/cti/feeds/{feed_id}")
def update_feed(feed_id: str, body: FeedUpdate):
    """Update an existing feed configuration."""
    r = _redis()
    patch = body.dict(exclude_none=True)
    found: dict = {}

    def _apply(feeds: list[dict]) -> list[dict]:
        found.clear()
        out = []
        for f in feeds:
            f = dict(f)
            if f["id"] == feed_id:
                f.update(patch)
                found["feed"] = f
            out.append(f)
        return out

    mutate_json(r, FEEDS_KEY, _apply, [])
    if "feed" not in found:
        raise HTTPException(status_code=404, detail="Feed not found")
    return found["feed"]


@router.delete("/cti/feeds/{feed_id}", status_code=204)
def delete_feed(feed_id: str):
    """Remove a feed and all its IOCs."""
    r = _redis()
    feeds = _load_feeds(r)
    feed = _find_feed(feeds, feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    # Remove IOCs belonging to this feed
    _remove_feed_iocs(r, feed_id)

    # Remove feed from list (atomic — a concurrent update can't resurrect it)
    mutate_json(r, FEEDS_KEY, lambda fs: [f for f in fs if f["id"] != feed_id], [])


@router.post("/cti/feeds/{feed_id}/pull")
def pull_feed(feed_id: str):
    """Manually pull IOCs from a feed now."""
    r = _redis()
    feeds = _load_feeds(r)
    feed = _find_feed(feeds, feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    feed_type = feed["type"]
    # Manual feeds with a URL can be re-pulled like a stix_url feed
    effective_type = feed_type
    if feed_type == "manual":
        if feed.get("url", "").strip():
            effective_type = "stix_url"
        else:
            raise HTTPException(
                status_code=400,
                detail="Pure manual feeds have no URL to pull from. Use POST /cti/import instead, or set a URL to enable periodic re-import.",
            )

    from citadel_contracts.logship import tool_logger
    aug = tool_logger("augur", r)
    aug.info("[Augur] downloading IOC feed '%s' (%s) from %s…",
             feed["name"], effective_type, feed.get("url", "?"))

    # Fetch FIRST — only replace existing IOCs once the new pull succeeds, so a
    # failed fetch never wipes the IOCs already loaded.
    try:
        if effective_type == "taxii":
            bundle = _taxii_fetch(feed)
            _remove_feed_iocs(r, feed_id)
            count = _process_stix_bundle(r, bundle, feed_id=feed_id, feed_name=feed["name"])
        elif effective_type == "stix_url":
            bundle = _stix_url_fetch(feed)
            _remove_feed_iocs(r, feed_id)
            count = _process_stix_bundle(r, bundle, feed_id=feed_id, feed_name=feed["name"])
        elif effective_type == "misp":
            attrs = _misp_fetch(feed)
            aug.info("[Augur] MISP returned %d attribute(s) for '%s'", len(attrs), feed["name"])
            _remove_feed_iocs(r, feed_id)
            count = _process_misp_attributes(r, attrs, feed_id=feed_id, feed_name=feed["name"])
        elif effective_type == "yeti":
            observables = _yeti_fetch(feed)
            _remove_feed_iocs(r, feed_id)
            count = _process_yeti_observables(r, observables, feed_id=feed_id, feed_name=feed["name"])
        else:
            raise HTTPException(status_code=400, detail=f"Unknown feed type: {feed_type}")
    except HTTPException as exc:
        aug.error("[Augur] feed '%s' download FAILED: %s", feed["name"], exc.detail)
        raise
    except Exception as exc:  # noqa: BLE001
        aug.error("[Augur] feed '%s' download FAILED: %s", feed["name"], exc)
        raise HTTPException(status_code=502, detail=f"Feed pull failed: {exc}")

    feed["last_pull"] = datetime.now(UTC).isoformat()
    feed["ioc_count"] = count
    _save_feeds(r, feeds)
    aug.info("[Augur] feed '%s' done: %d IOC(s) stored (deduped)", feed["name"], count)

    return {"feed_id": feed_id, "iocs_imported": count, "last_pull": feed["last_pull"]}


# ── Direct STIX import ──────────────────────────────────────────────────────


@router.post("/cti/import")
def import_bundle(body: BundleImport):
    """
    Import a STIX 2.1 bundle JSON directly.

    Parses indicator objects, extracts patterns (hash, ip, domain, url,
    email, filename), and stores each IOC in Redis with source metadata.
    """
    bundle = body.bundle
    if not isinstance(bundle, dict):
        raise HTTPException(status_code=422, detail="Bundle must be a JSON object.")

    r = _redis()
    count = _process_stix_bundle(r, bundle, feed_id="manual", feed_name="Manual Import")
    return {"iocs_imported": count}


# ── IOC endpoints ────────────────────────────────────────────────────────────


@router.get("/cti/iocs")
def list_iocs(
    type: str | None = Query(None, description="Filter by IOC type"),
    q: str | None = Query(None, description="Search IOC values"),
    visibility: str | None = Query(None, description="ip scope: public | private"),
    include_expired: bool = Query(False, description="include expired IOCs"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
):
    """List IOCs with filtering + pagination.

    Feeds can hold hundreds of thousands of IOCs, so we DON'T load every entry
    per request. ``total`` comes from O(1) HLEN; the page is collected via HSCAN
    with an early stop. (Deep, globally-sorted pagination over ~1M IOCs isn't the
    job here — this is a browser; use search to find a specific value fast.)"""
    r = _redis()
    types_to_scan = [type] if type and type in IOC_TYPES else list(IOC_TYPES)
    ql = q.lower() if q else None

    # O(1) total per type.
    total = 0
    for ioc_type in types_to_scan:
        type_key = rk.cti_ioc_type(ioc_type)
        _ensure_ioc_hash(r, type_key)
        try:
            total += r.hlen(type_key)
        except Exception:
            pass

    need = page * size          # how many filtered rows we must reach
    collected: list[dict] = []
    cap = max(need * 4, 2000)    # bound the scan so a huge feed can't stall us
    scanned = 0
    for ioc_type in types_to_scan:
        type_key = rk.cti_ioc_type(ioc_type)
        cursor = 0
        while True:
            cursor, batch = r.hscan(type_key, cursor=cursor, count=500,
                                    match=(f"*{ql}*" if ql else None))
            for m in batch.values():
                scanned += 1
                try:
                    obj = json.loads(m)
                except (json.JSONDecodeError, TypeError):
                    continue
                if not include_expired and _ioc_expired(obj):
                    continue
                if visibility == "public" and obj.get("is_private"):
                    continue
                if visibility == "private" and not obj.get("is_private"):
                    continue
                collected.append(obj)
            if cursor == 0 or len(collected) >= need or scanned >= cap:
                break
        if len(collected) >= need or scanned >= cap:
            break

    collected.sort(key=lambda x: x.get("created", ""), reverse=True)
    start = (page - 1) * size
    page_iocs = collected[start:start + size]

    return {
        "iocs": page_iocs,
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size if total > 0 else 0,
        "sampled": scanned >= cap,  # true → page is a bounded sample, not global sort
    }


@router.get("/cti/iocs/stats")
def ioc_stats():
    """Count IOCs by type."""
    r = _redis()
    stats: dict[str, int] = {}
    total = 0
    for ioc_type in IOC_TYPES:
        type_key = rk.cti_ioc_type(ioc_type)
        _ensure_ioc_hash(r, type_key)
        count = r.hlen(type_key)
        stats[ioc_type] = count
        total += count
    stats["total"] = total
    return stats


@router.delete("/cti/iocs", status_code=204)
def clear_iocs():
    """Clear all IOCs from the database."""
    r = _redis()
    # Remove all type sets
    for ioc_type in IOC_TYPES:
        type_key = rk.cti_ioc_type(ioc_type)
        _ensure_ioc_hash(r, type_key)
        # Clean up detail/hash keys
        for m in r.hvals(type_key):
            try:
                obj = json.loads(m)
                if obj.get("indicator_id"):
                    r.delete(rk.cti_ioc_detail(obj["indicator_id"]))
                if obj.get("type") == "hash":
                    r.delete(rk.cti_ioc_hash(obj["value"]))
            except (json.JSONDecodeError, TypeError):
                pass
        r.delete(type_key)

    # Reset IOC counts on all feeds
    feeds = _load_feeds(r)
    for feed in feeds:
        feed["ioc_count"] = 0
    _save_feeds(r, feeds)


def _purge_expired_iocs(r: redis_lib.Redis) -> int:
    """Drop IOCs past their valid_until across all type hashes. Returns count."""
    removed = 0
    for ioc_type in IOC_TYPES:
        type_key = rk.cti_ioc_type(ioc_type)
        _ensure_ioc_hash(r, type_key)
        stale = []
        for field, m in r.hgetall(type_key).items():
            try:
                obj = json.loads(m)
            except (json.JSONDecodeError, TypeError):
                continue
            if _ioc_expired(obj):
                stale.append(field)
                if obj.get("indicator_id"):
                    r.delete(rk.cti_ioc_detail(obj["indicator_id"]))
                if ioc_type == "hash":
                    r.delete(rk.cti_ioc_hash(obj["value"]))
        if stale:
            r.hdel(type_key, *stale)
            removed += len(stale)
    return removed


@router.post("/cti/iocs/purge-expired")
def purge_expired_iocs():
    """Remove all expired IOCs now (also runs periodically in the scheduler)."""
    removed = _purge_expired_iocs(_redis())
    return {"removed": removed}


@router.get("/cti/own-networks")
def get_own_networks():
    """The operator's own public networks (CIDRs) used to flag/ filter own infra."""
    r = _redis()
    raw = r.get(_OWN_NETWORKS_KEY)
    try:
        cidrs = json.loads(raw) if raw else []
    except (json.JSONDecodeError, TypeError):
        cidrs = []
    return {"cidrs": cidrs}


@router.put("/cti/own-networks")
def set_own_networks(body: dict):
    """Set the operator's own public networks. Validates CIDRs, refreshes cache,
    and re-flags existing IP IOCs so the public/private/own split stays correct."""
    global _OWN_NETS_CACHE
    raw_cidrs = body.get("cidrs", [])
    valid: list[str] = []
    for c in raw_cidrs:
        try:
            valid.append(str(ipaddress.ip_network(str(c).strip(), strict=False)))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"invalid CIDR: {c}")
    r = _redis()
    r.set(_OWN_NETWORKS_KEY, json.dumps(valid))
    _OWN_NETS_CACHE = None  # force reload

    # Re-flag existing IP IOCs against the new own-networks list.
    type_key = rk.cti_ioc_type("ip")
    _ensure_ioc_hash(r, type_key)
    reflagged = 0
    for field, m in r.hgetall(type_key).items():
        try:
            obj = json.loads(m)
        except (json.JSONDecodeError, TypeError):
            continue
        own = _ip_is_own(obj.get("value", ""), r)
        if obj.get("is_own") != own:
            obj["is_own"] = own
            r.hset(type_key, field, json.dumps(obj, sort_keys=True))
            reflagged += 1
    return {"cidrs": valid, "reflagged": reflagged}


# ── Allowlist endpoints (known-good values suppressed from IOC matches) ──────

@router.get("/cti/allowlist")
def get_allowlist(case_id: str | None = Query(None)):
    """Allowlisted known-good values, grouped by type. Merges global + case scope."""
    r = _redis()
    merged = _load_allowlist(r, case_id)
    return {"allowlist": {t: sorted(merged.get(t, [])) for t in _ALLOWLIST_TYPES if merged.get(t)},
            "scope": case_id or "_global"}


@router.put("/cti/allowlist")
def set_allowlist(body: dict):
    """Replace the allowlist for a scope. Body: {values: ["8.8.8.8", "evil-but-known.com", ...],
    case_id?: "..."}. Each value is auto-classified by type. Use case_id to scope to one case;
    omit for the global allowlist."""
    r = _redis()
    case_id = body.get("case_id")
    scope = case_id or "_global"
    values = body.get("values") or []
    grouped: dict[str, list[str]] = {}
    for v in values:
        v = str(v).strip()
        if not v:
            continue
        grouped.setdefault(_classify_allowlist_value(v), []).append(v.lower())
    # Replace every type set for this scope (so removals take effect).
    for t in _ALLOWLIST_TYPES:
        key = _allowlist_key(scope, t)
        r.delete(key)
        if grouped.get(t):
            r.sadd(key, *set(grouped[t]))
    total = sum(len(set(v)) for v in grouped.values())
    return {"scope": scope, "count": total,
            "allowlist": {t: sorted(set(v)) for t, v in grouped.items()}}


# ── Case IOC matching ────────────────────────────────────────────────────────

# Fields to check against each IOC type when scanning case events
_MATCH_FIELDS: dict[str, list[str]] = {
    "hash": [
        "process.hash.md5",
        "process.hash.sha1",
        "process.hash.sha256",
        "file.hash.md5",
        "file.hash.sha1",
        "file.hash.sha256",
        "message",
    ],
    "ip": [
        "network.src_ip",
        "network.dst_ip",
        "network.dest_ip",
        "source.ip",
        "destination.ip",
        "message",
    ],
    "domain": ["dns.question.name", "url.domain", "host.hostname", "message"],
    "url": ["url.full", "url.original", "message"],
    "email": ["email.from.address", "email.to.address", "user.email", "message"],
    "filename": ["file.name", "process.executable", "process.name", "message"],
}

# Size of ES scroll batches when scanning events
_MATCH_BATCH_SIZE = 500


def _get_nested(doc: dict, dotted_key: str) -> Any:
    """Safely traverse a nested dict by dotted key path."""
    parts = dotted_key.split(".")
    current: Any = doc
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


# Token extractors for the free-text `message` field. Testing every IOC against
# each message is O(iocs) per event — at ~1M IOCs that pegs a CPU core for the
# whole scan and (GIL) stalls the API. Instead we pull type-shaped candidate
# tokens out of the message and do O(1) dict lookups: O(message length) per
# event regardless of IOC-DB size.
_RX_IP = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]*")
_RX_DOMAIN = re.compile(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}")
_RX_URL = re.compile(r"https?://[^\s\"'<>]+")
_RX_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_RX_HASH = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_RX_FILE = re.compile(r"[^\s\\/]+\.[A-Za-z0-9]{1,8}")
_MSG_EXTRACTORS: dict[str, re.Pattern] = {
    "ip": _RX_IP, "domain": _RX_DOMAIN, "url": _RX_URL,
    "email": _RX_EMAIL, "hash": _RX_HASH, "filename": _RX_FILE,
}

# Parsed-IOC lookup cache. Re-reading + JSON-parsing the whole IOC DB on every
# match call is itself expensive; the DB changes slowly, so cache briefly.
_IOC_LOOKUP_CACHE: dict = {"at": 0.0, "data": None}
_IOC_LOOKUP_TTL = 60.0


# ── Allowlists (known-good values suppressed from matches) ───────────────────
_ALLOWLIST_TYPES = ("ip", "domain", "url", "hash", "email", "filename", "process")


def _allowlist_key(scope: str, t: str) -> str:
    return f"fo:allowlist:{scope}:{t}"


def _classify_allowlist_value(v: str) -> str:
    """Best-effort type for a free-form allowlist entry (so the UI can stay one box)."""
    v = v.strip()
    low = v.lower()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if "@" in v:
        return "email"
    if re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", low):
        return "hash"
    if low.startswith(("http://", "https://")):
        return "url"
    if "." in v and "/" not in v and " " not in v:
        return "domain"
    return "process"


def _load_allowlist(r, case_id: str | None = None) -> dict[str, set]:
    """{type -> set(lowercased values)} merged from the global + case scope."""
    out: dict[str, set] = {}
    scopes = ["_global"] + ([case_id] if case_id else [])
    for t in _ALLOWLIST_TYPES:
        vals: set = set()
        for scope in scopes:
            try:
                vals |= {str(v).lower() for v in r.smembers(_allowlist_key(scope, t))}
            except Exception:
                pass
        if vals:
            out[t] = vals
    return out


def _ioc_lookups(r) -> dict[str, dict[str, dict]]:
    """{type -> {value_lower: ioc_obj}} for all non-expired IOCs, cached 60 s."""
    import time

    now = time.monotonic()
    c = _IOC_LOOKUP_CACHE
    if c["data"] is not None and (now - c["at"]) < _IOC_LOOKUP_TTL:
        return c["data"]
    ioc_sets: dict[str, dict[str, dict]] = {}
    for ioc_type in IOC_TYPES:
        type_key = rk.cti_ioc_type(ioc_type)
        _ensure_ioc_hash(r, type_key)
        lookup: dict[str, dict] = {}
        for m in r.hvals(type_key):
            try:
                obj = json.loads(m)
                if _ioc_expired(obj):
                    continue  # don't match against stale intel
                val = (obj.get("value") or "").lower()
                if val:
                    lookup[val] = obj
            except (json.JSONDecodeError, TypeError):
                pass
        if lookup:
            ioc_sets[ioc_type] = lookup
    c["data"] = ioc_sets
    c["at"] = now
    return ioc_sets


# Structured (exact-value) fields per IOC type — the `message` free-text field
# is intentionally excluded from aggregation matching: at 10M+ events it cannot
# be aggregated, and substring scanning every event is what made matching
# unusable. Structured fields cover the real signal (the actual IP/host/hash).
_AGG_FIELDS: dict[str, list[str]] = {
    t: [f for f in fields if f != "message"] for t, fields in _MATCH_FIELDS.items()
}
_AGG_MAX_TERMS = 20000  # distinct values pulled per field (top-N by frequency)


def _es_terms_agg(index: str, field: str, size: int = _AGG_MAX_TERMS) -> list[tuple[str, int]]:
    """Distinct values of a structured field present in the case, with event
    counts — computed server-side by Elasticsearch (one query, no event scan).

    Returns [(value, doc_count), …]. Falls back to the ``.keyword`` subfield for
    analyzed text fields; returns [] if the field is absent or non-aggregatable.
    """
    for fld in (field, f"{field}.keyword"):
        body = {"size": 0, "aggs": {"v": {"terms": {"field": fld, "size": size}}}}
        try:
            resp = es_req("POST", f"/{index}/_search", body)
        except Exception:
            continue  # text field w/o fielddata → try .keyword
        buckets = resp.get("aggregations", {}).get("v", {}).get("buckets")
        if buckets is not None:
            return [(str(b["key"]), int(b.get("doc_count", 0))) for b in buckets if b.get("key") is not None]
    return []


@router.post("/cases/{case_id}/cti/match")
def match_case_iocs(
    case_id: str,
    types: str | None = Query(None),
    _case: dict = Depends(require_case_access),
):
    """Match a case's events against the IOC DB — FAST, via aggregation.

    Instead of scanning every event (hopeless at 10M+ events), Elasticsearch
    returns the distinct structured values present in the case (IPs, hostnames,
    hashes, domains, …) with their event counts; we intersect those with the IOC
    database. The result is a short list of *distinct enriched indicators* —
    value, how many events it touched, the feed it came from, threat type,
    confidence, severity — not millions of per-event rows.

    `types` (comma-separated, e.g. ``ip,domain``) narrows which IOC types to
    check. Own/private indicators are tagged (``severity: info``) so the real
    external hits stand out.
    """
    r = _redis()
    ioc_sets = _ioc_lookups(r)
    if not ioc_sets:
        return {"indicators": [], "indicator_count": 0, "message": "No IOCs loaded"}

    requested = [t.strip() for t in types.split(",")] if types else list(IOC_TYPES)
    sel_types = [t for t in requested if t in ioc_sets]
    index = f"fo-case-{case_id}-*"
    allow = _load_allowlist(r, case_id)  # known-good → suppressed (severity info)

    # value_lower -> aggregated indicator
    indicators: dict[str, dict] = {}
    truncated: list[str] = []

    for ioc_type in sel_types:
        lookup = ioc_sets[ioc_type]
        for field in _AGG_FIELDS.get(ioc_type, []):
            buckets = _es_terms_agg(index, field)
            if len(buckets) >= _AGG_MAX_TERMS:
                truncated.append(field)
            for value, count in buckets:
                obj = lookup.get(value.lower())
                if not obj:
                    continue
                key = f"{ioc_type}:{value.lower()}"
                ind = indicators.get(key)
                if ind:
                    ind["event_count"] += count
                    if field not in ind["matched_fields"]:
                        ind["matched_fields"].append(field)
                else:
                    is_own = bool(obj.get("is_own"))
                    is_private = bool(obj.get("is_private"))
                    is_allow = value.lower() in allow.get(ioc_type, ())
                    indicators[key] = {
                        "ioc_type": ioc_type,
                        "ioc_value": obj.get("value", value),
                        "event_count": count,
                        "matched_fields": [field],
                        "indicator_id": obj.get("indicator_id", ""),
                        "feed_name": obj.get("feed_name", ""),
                        "threat_type": obj.get("threat_type", ""),
                        "confidence": obj.get("confidence", ""),
                        "tags": obj.get("tags", ""),
                        "first_seen": obj.get("first_seen", ""),
                        "last_seen": obj.get("last_seen", ""),
                        "severity": "info" if (is_own or is_private or is_allow) else "high",
                        "is_own": is_own,
                        "is_private": is_private,
                        "allowlisted": is_allow,
                    }

    out = sorted(
        indicators.values(),
        key=lambda i: (i["severity"] != "high", -i["event_count"]),
    )
    real = [i for i in out if i["severity"] == "high"]
    return {
        "indicators": out,
        "indicator_count": len(out),
        "real_count": len(real),
        "own_or_private_count": len(out) - len(real),
        "total_event_hits": sum(i["event_count"] for i in out),
        "iocs_in_db": sum(len(v) for v in ioc_sets.values()),
        "types": sel_types,
        "method": "aggregation",
        "truncated_fields": sorted(set(truncated)),
    }


@router.get("/cases/{case_id}/cti/indicator-events")
def cti_indicator_events(
    case_id: str,
    type: str = Query(...),
    value: str = Query(...),
    limit: int = Query(25),
    _case: dict = Depends(require_case_access),
):
    """Drill-down: the events in a case that contain one matched indicator.

    Targeted query (only the matching events) — used when an analyst clicks an
    indicator in the match results, so the heavy work never happens up front.
    """
    fields = _AGG_FIELDS.get(type, [])
    if not fields:
        raise HTTPException(status_code=400, detail=f"unknown IOC type '{type}'")
    index = f"fo-case-{case_id}-*"
    should = [{"term": {f: value}} for f in fields] + [{"term": {f"{f}.keyword": value}} for f in fields]
    body = {
        "query": {"bool": {"should": should, "minimum_should_match": 1}},
        "size": max(1, min(limit, 200)),
        "_source": ["fo_id", "timestamp", "message", "host", "artifact_type"],
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    try:
        resp = es_req("POST", f"/{index}/_search", body)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"ES query failed: {exc}")
    hits = resp.get("hits", {}).get("hits", [])
    total = resp.get("hits", {}).get("total", {})
    return {
        "events": [
            {
                "fo_id": h["_source"].get("fo_id", h.get("_id", "")),
                "timestamp": h["_source"].get("timestamp", ""),
                "message": h["_source"].get("message", ""),
                "artifact_type": h["_source"].get("artifact_type", ""),
                "host": (h["_source"].get("host") or {}).get("hostname", "")
                if isinstance(h["_source"].get("host"), dict) else "",
            }
            for h in hits
        ],
        "total": total.get("value", len(hits)) if isinstance(total, dict) else len(hits),
    }
