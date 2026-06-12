"""Search and timeline endpoints."""

from __future__ import annotations

import json

import agg_rules
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from services import elasticsearch as es
from services.cases import get_case

router = APIRouter(tags=["search"])


@router.get("/cases/{case_id}/timeline")
def get_timeline(
    case_id: str,
    artifact_type: str | None = None,
    from_ts: str | None = Query(None, alias="from"),
    to_ts: str | None = Query(None, alias="to"),
    sort_field: str = "timestamp",
    sort_order: str = "asc",
    page: int = 0,
    size: int = Query(100, le=1000),
    search_after: str | None = None,
):
    """
    Paginated cross-artifact timeline for a case.
    Use artifact_type to filter to a specific index (e.g. evtx, prefetch).
    Pass ``search_after`` (the prior page's ``next_search_after``) to page past
    the 10k window on large cases.
    """
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")

    sa = None
    if search_after:
        try:
            sa = json.loads(search_after)
        except (json.JSONDecodeError, ValueError):
            sa = None

    result = es.search_events(
        case_id=case_id,
        artifact_type=artifact_type,
        from_ts=from_ts,
        to_ts=to_ts,
        page=page,
        size=size,
        sort_field=sort_field,
        sort_order=sort_order,
        search_after=sa,
    )

    hits = result.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    raw_hits = hits.get("hits", [])
    events = [h["_source"] for h in raw_hits]
    next_cursor = raw_hits[-1].get("sort") if raw_hits else None

    return {
        "case_id": case_id,
        "total": total,
        "page": page,
        "size": size,
        "artifact_type": artifact_type,
        "events": events,
        "next_search_after": json.dumps(next_cursor) if next_cursor else None,
    }


@router.get("/cases/{case_id}/search")
def search(
    case_id: str,
    q: str = "",
    artifact_type: str | None = None,
    from_ts: str | None = Query(None, alias="from"),
    to_ts: str | None = Query(None, alias="to"),
    hostname: str | None = None,
    username: str | None = None,
    event_id: int | None = None,
    channel: str | None = None,
    src_ip: str | None = None,
    dest_ip: str | None = None,
    status_code: int | None = None,
    http_method: str | None = None,
    domain: str | None = None,
    flagged: bool | None = None,
    tags: list[str] | None = Query(None),
    regexp: bool = False,
    sort_field: str = "timestamp",
    sort_order: str = "asc",
    page: int = 0,
    size: int = Query(50, le=1000),
    search_after: str | None = None,
):
    """Full-text + field-level search within a case.

    Pass ``search_after`` (the ``next_search_after`` cursor from a prior page) to
    page past the 10k window — shallow ``page`` paging only works for the first
    pages, which matters on multi-million-event cases.
    """
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")

    sa = None
    if search_after:
        try:
            sa = json.loads(search_after)
        except (json.JSONDecodeError, ValueError):
            sa = None

    extra_filters = []
    if hostname:
        extra_filters.append({"term": {"host.hostname.keyword": hostname}})
    if username:
        extra_filters.append({"term": {"user.name.keyword": username}})
    if event_id is not None:
        extra_filters.append({"term": {"evtx.event_id": event_id}})
    if channel:
        extra_filters.append({"term": {"evtx.channel.keyword": channel}})
    if src_ip:
        extra_filters.append({"term": {"network.src_ip": src_ip}})
    if dest_ip:
        extra_filters.append({"term": {"network.dst_ip": dest_ip}})
    if status_code is not None:
        extra_filters.append({"term": {"http.status_code": status_code}})
    if http_method:
        extra_filters.append({"term": {"http.method.keyword": http_method}})
    if domain:
        extra_filters.append({"term": {"dns.question.name.keyword": domain}})
    if flagged is not None:
        extra_filters.append({"term": {"is_flagged": flagged}})
    if tags:
        extra_filters.append({"terms": {"tags": tags}})

    result = es.search_events(
        case_id=case_id,
        query=q,
        artifact_type=artifact_type,
        from_ts=from_ts,
        to_ts=to_ts,
        extra_filters=extra_filters,
        page=page,
        size=size,
        regexp=regexp,
        sort_field=sort_field,
        sort_order=sort_order,
        search_after=sa,
    )

    hits = result.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    raw_hits = hits.get("hits", [])
    events = [{"_id": h["_id"], "_index": h["_index"], **h["_source"]} for h in raw_hits]
    # Cursor for the next page (deep pagination beyond the 10k window).
    next_cursor = raw_hits[-1].get("sort") if raw_hits else None

    return {
        "case_id": case_id,
        "query": q,
        "total": total,
        "page": page,
        "size": size,
        "events": events,
        "next_search_after": json.dumps(next_cursor) if next_cursor else None,
    }


@router.get("/cases/{case_id}/search/facets")
def get_facets(
    case_id: str,
    q: str = "",
    artifact_type: str | None = None,
    from_ts: str | None = None,
    to_ts: str | None = None,
):
    """Aggregation facets for the search filter panel.

    ``from_ts``/``to_ts`` (ISO8601) scope the activity histogram so it rescales
    to the zoomed range instead of always bucketing by day.
    """
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")

    aggs = es.get_search_facets(
        case_id, query=q, artifact_type=artifact_type, from_ts=from_ts, to_ts=to_ts
    )
    return {"case_id": case_id, "facets": aggs}


@router.get("/cases/{case_id}/events/{fo_id}")
def get_event(case_id: str, fo_id: str):
    """Fetch a single event by ID (full document including raw)."""
    event = es.get_event_by_id(case_id, fo_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


class TagUpdate(BaseModel):
    tags: list[str]


class NoteUpdate(BaseModel):
    note: str


@router.put("/cases/{case_id}/events/{fo_id}/tag")
def tag_event(case_id: str, fo_id: str, body: TagUpdate):
    """Set tags on an event."""
    event = es.get_event_by_id(case_id, fo_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    index = event.get("_index", f"fo-case-{case_id}-generic")
    doc_id = event.get("_id", fo_id)
    success = es.update_event(case_id, index, doc_id, {"tags": body.tags})
    if not success:
        raise HTTPException(status_code=500, detail="Update failed")
    return {"fo_id": fo_id, "tags": body.tags}


@router.put("/cases/{case_id}/events/{fo_id}/flag")
def flag_event(case_id: str, fo_id: str):
    """Toggle the is_flagged field on an event."""
    event = es.get_event_by_id(case_id, fo_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    new_flag = not event.get("is_flagged", False)
    index = event.get("_index", f"fo-case-{case_id}-generic")
    doc_id = event.get("_id", fo_id)
    es.update_event(case_id, index, doc_id, {"is_flagged": new_flag})
    return {"fo_id": fo_id, "is_flagged": new_flag}


class PinUpdate(BaseModel):
    pinned: bool | None = None  # None = toggle
    note: str = ""


@router.put("/cases/{case_id}/events/{fo_id}/pin")
def pin_event(case_id: str, fo_id: str, body: PinUpdate):
    """Toggle/set the is_pinned field. Pin = 'curated evidence for the report',
    distinct from flag ('triage me later'). Optional note explains why pinned."""
    event = es.get_event_by_id(case_id, fo_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    new_pinned = (not event.get("is_pinned", False)) if body.pinned is None else bool(body.pinned)
    index = event.get("_index", f"fo-case-{case_id}-generic")
    doc_id = event.get("_id", fo_id)
    patch = {"is_pinned": new_pinned}
    if body.note is not None:
        patch["pin_note"] = body.note
    es.update_event(case_id, index, doc_id, patch)
    return {"fo_id": fo_id, "is_pinned": new_pinned, "pin_note": body.note or ""}


@router.get("/cases/{case_id}/pinned")
def list_pinned(case_id: str, size: int = Query(100, le=500)):
    """Return all pinned events for a case, newest pin first."""
    import urllib.error

    from services.elasticsearch import _request as es_req

    body = {
        "query": {"term": {"is_pinned": True}},
        "size": size,
        "sort": [{"timestamp": {"order": "asc", "unmapped_type": "keyword", "missing": "_last"}}],
    }
    try:
        res = es_req("POST", f"/fo-case-{case_id}-*/_search", body)
    except (urllib.error.HTTPError, Exception):
        return {"events": [], "total": 0}
    hits = res.get("hits", {}).get("hits", [])
    total = res.get("hits", {}).get("total", {}).get("value", 0)
    return {
        "events": [{"_id": h["_id"], "_index": h["_index"], **h["_source"]} for h in hits],
        "total": total,
    }


@router.put("/cases/{case_id}/events/{fo_id}/note")
def note_event(case_id: str, fo_id: str, body: NoteUpdate):
    """Set an analyst note on an event."""
    event = es.get_event_by_id(case_id, fo_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    index = event.get("_index", f"fo-case-{case_id}-generic")
    doc_id = event.get("_id", fo_id)
    es.update_event(case_id, index, doc_id, {"analyst_note": body.note})
    return {"fo_id": fo_id, "analyst_note": body.note}


@router.get("/cases/{case_id}/iocs")
def get_iocs(case_id: str, size: int = Query(50, le=200)):
    """
    Return the top observed values for IOC-relevant fields across the whole case.
    Each category is an aggregation bucket list: [{value, count}].

    Field mappings vary across indices (text+keyword, bare keyword, ip type).
    We probe the live mapping once per IOC field and pick an agg-friendly path
    so old + new indices all contribute results.
    """
    import urllib.error

    from services.elasticsearch import _request as es_req

    index = f"fo-case-{case_id}-*"

    # Canonical (preferred) field path per IOC category. Probe is best-effort.
    IOC_FIELDS = {
        "src_ips": "network.src_ip",
        "dst_ips": "network.dst_ip",
        "hostnames": "host.hostname",
        "usernames": "user.name",
        "processes": "process.name",
        "executables": "process.executable_name",
        "domains": "network.dst_domain",
        "urls": "http.request_path",
        "user_agents": "http.user_agent",
        "cmdlines": "process.command_line",
        "hashes_md5": "process.hash_md5",
        "hashes_sha256": "process.hash_sha256",
        "reg_keys": "registry.key_path",
    }

    # Probe the mapping for each canonical field; pick the right agg path:
    # - keyword/ip → use base path directly (agg-friendly)
    # - text       → use .keyword subfield
    # - missing    → fall back to base path (agg returns empty, no error)
    def pick_agg_path(canonical: str) -> str:
        try:
            mp = es_req("GET", f"/{index}/_mapping/field/{canonical}")
            for _, body in (mp or {}).items():
                m = body.get("mappings", {}).get(canonical, {}).get("mapping", {})
                if not m:
                    continue
                leaf = next(iter(m.values()))
                ftype = leaf.get("type") if isinstance(leaf, dict) else None
                if ftype == "text":
                    return f"{canonical}.keyword"
                if ftype in ("keyword", "ip", "long", "short", "integer"):
                    return canonical
            return f"{canonical}.keyword"  # default guess for unmapped
        except Exception:
            return f"{canonical}.keyword"

    resolved = {key: pick_agg_path(canon) for key, canon in IOC_FIELDS.items()}
    body = {
        "size": 0,
        "aggs": {key: {"terms": {"field": path, "size": size}} for key, path in resolved.items()},
    }

    try:
        result = es_req("POST", f"/{index}/_search", body)
        aggs = result.get("aggregations", {})

        def buckets(key):
            return [
                {"value": b["key"], "count": b["doc_count"]}
                for b in aggs.get(key, {}).get("buckets", [])
                if b.get("key") not in (None, "", "-")
            ]

        return {key: buckets(key) for key in IOC_FIELDS}
    except (urllib.error.HTTPError, Exception):
        return {k: [] for k in IOC_FIELDS}


@router.get("/cases/{case_id}/fields")
def list_fields(case_id: str):
    """
    Return all indexed fields across the case's indices, grouped by namespace.
    Used by the Timeline field explorer + search autocomplete.

    Output: { groups: [{ prefix, fields: [{name, type, searchable}] }], total }
    """
    import urllib.error

    from services.elasticsearch import _request as es_req

    try:
        res = es_req("GET", f"/fo-case-{case_id}-*/_mapping/field/*")
    except (urllib.error.HTTPError, Exception):
        return {"groups": [], "total": 0}

    fields: dict[str, str] = {}  # name -> ES type
    for idx, body in (res or {}).items():
        mappings = body.get("mappings", {}) or {}
        for fname, fmeta in mappings.items():
            if fname.startswith("_"):
                continue
            inner = fmeta.get("mapping", {}) or {}
            # fmeta.mapping is keyed by the leaf name; grab the only value
            if isinstance(inner, dict) and inner:
                leaf = next(iter(inner.values()))
                ftype = leaf.get("type", "object") if isinstance(leaf, dict) else "object"
            else:
                ftype = "object"
            # Hide raw + internal text subfields we don't search directly
            if fname.startswith("raw"):
                continue
            fields[fname] = ftype

    # Group by namespace prefix (host, user, process, network, …)
    groups: dict[str, list[dict]] = {}
    for name, ftype in sorted(fields.items()):
        prefix = name.split(".", 1)[0] if "." in name else "_root"
        groups.setdefault(prefix, []).append(
            {
                "name": name,
                "type": ftype,
                "searchable": ftype not in ("object", "nested"),
            }
        )

    return {
        "groups": [
            {"prefix": p, "fields": flist}
            for p, flist in sorted(groups.items(), key=lambda kv: (kv[0] == "_root", kv[0]))
        ],
        "total": len(fields),
    }


@router.get("/cases/{case_id}/mitre/coverage")
def mitre_coverage(case_id: str):
    """
    Return MITRE ATT&CK coverage for a case.

    Output: {
      "techniques": [{technique_id, technique_name, tactic, count}],
      "by_tactic":  { "Initial Access": 23, "Execution": 117, ... },
      "total_events_with_mitre": N,
    }

    Powers a heatmap on the case page — analysts see which techniques have
    evidence at a glance.
    """
    import urllib.error

    from services.elasticsearch import _request as es_req

    index = f"fo-case-{case_id}-*"
    # Plugins emit mitre.id / mitre.technique / mitre.tactic (registry plugin,
    # persistence module, etc). The old `mitre.technique_id` shape never
    # actually landed — keep both probes so Hayabusa-style payloads stay
    # forward-compatible.
    body = {
        "size": 0,
        "query": {
            "bool": {
                "should": [
                    {"exists": {"field": "mitre.id"}},
                    {"exists": {"field": "mitre.technique_id"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "by_technique": {
                # mitre.id is text in current mappings; aggregate on .keyword.
                "terms": {"field": "mitre.id.keyword", "size": 200},
                "aggs": {
                    "top_name": {"terms": {"field": "mitre.technique.keyword", "size": 1}},
                    # mitre.tactic was mapped as keyword directly (no .keyword
                    # subfield) — using the parent path here.
                    "top_tactic": {"terms": {"field": "mitre.tactic", "size": 1}},
                },
            },
            "by_tactic": {"terms": {"field": "mitre.tactic", "size": 30}},
        },
    }
    try:
        res = es_req("POST", f"/{index}/_search", body)
    except (urllib.error.HTTPError, Exception) as exc:
        raise HTTPException(status_code=400, detail=f"MITRE coverage failed: {exc}")

    aggs = res.get("aggregations", {})
    total_evts = res.get("hits", {}).get("total", {}).get("value", 0)
    techniques = []
    for b in aggs.get("by_technique", {}).get("buckets", []):
        name_buckets = b.get("top_name", {}).get("buckets", [])
        tactic_buckets = b.get("top_tactic", {}).get("buckets", [])
        techniques.append(
            {
                "technique_id": b["key"],
                "technique_name": name_buckets[0]["key"] if name_buckets else b["key"],
                "tactic": tactic_buckets[0]["key"] if tactic_buckets else "",
                "count": b["doc_count"],
            }
        )
    by_tactic = {b["key"]: b["doc_count"] for b in aggs.get("by_tactic", {}).get("buckets", [])}
    return {
        "techniques": techniques,
        "by_tactic": by_tactic,
        "total_events_with_mitre": total_evts,
    }


@router.post("/search/cross")
def search_cross_case(body: dict):
    """
    Run a single Lucene query across ALL accessible cases.

    Request: {
      "query": "process.executable_name:powershell.exe AND user.name:admin",
      "size_per_case": 3        # sample events to return per matching case
    }

    Response: {
      "query": "...",
      "total_cases":   N,
      "matching_cases": M,
      "results": [
        {
          "case_id": "...",
          "case_name": "...",
          "company": "...",
          "hits": 1234,
          "samples": [ {ev}, ... ]
        }, ...
      ]
    }

    Used for: hunt the same IOC across investigations (repeat offenders,
    cross-engagement intel, watchlist matches). RBAC-aware — companies the
    caller can't see are skipped.
    """
    import urllib.error

    from services import cases as case_svc
    from services.elasticsearch import _request as es_req
    from services.elasticsearch import search_events

    query = (body.get("query") or "").strip()
    if not query:
        raise HTTPException(status_code=400, detail="query is required")
    size = int(body.get("size_per_case") or 3)
    size = max(0, min(size, 25))

    cases = case_svc.list_cases()
    if not cases:
        return {"query": query, "total_cases": 0, "matching_cases": 0, "results": []}

    # Tally per-case hit counts in a single multi-index agg
    agg_body = {
        "size": 0,
        "query": {
            "query_string": {
                "query": query,
                "default_operator": "AND",
                "fields": ["*"],
                "allow_leading_wildcard": True,
                "analyze_wildcard": True,
            }
        },
        "aggs": {"by_case": {"terms": {"field": "case_id", "size": 1000}}},
    }
    try:
        agg = es_req("POST", "/fo-case-*/_search", agg_body)
    except (urllib.error.HTTPError, Exception) as exc:
        raise HTTPException(status_code=400, detail=f"Cross-case search failed: {exc}")

    buckets = (agg.get("aggregations", {}).get("by_case", {}) or {}).get("buckets", [])
    counts = {b["key"]: b["doc_count"] for b in buckets}

    by_id = {c["case_id"]: c for c in cases}
    results = []
    for cid, hit_count in sorted(counts.items(), key=lambda kv: -kv[1]):
        case = by_id.get(cid)
        if not case:
            continue  # case index without metadata (e.g. archived/purged)
        samples: list[dict] = []
        if size > 0:
            try:
                r = search_events(
                    cid, query=query, size=size, sort_field="timestamp", sort_order="desc"
                )
                samples = [h.get("_source", h) for h in r.get("hits", {}).get("hits", [])]
            except Exception:
                samples = []
        results.append(
            {
                "case_id": cid,
                "case_name": case.get("name", cid),
                "company": case.get("company", ""),
                "status": case.get("status", ""),
                "hits": hit_count,
                "samples": samples,
            }
        )

    return {
        "query": query,
        "total_cases": len(cases),
        "matching_cases": len(results),
        "results": results,
    }


@router.get("/cases/{case_id}/aggregate")
def aggregate(
    case_id: str,
    field: str = Query(..., min_length=1),
    agg: str = Query(
        "terms",
        regex="^(terms|sum|avg|min|max|cardinality|stats|histogram|date_histogram|percentiles)$",
    ),
    q: str = "",
    size: int = Query(20, ge=1, le=200),
    interval: str = "1d",
    bucket_size: float = 1.0,
    sub_card: str = "",  # comma-separated fields; computes cardinality per bucket
):
    """
    Run an arbitrary aggregation on a field with optional Lucene filter.

    agg types:
      terms          — bucket count per distinct value (top N). Pass
                       comma-separated `field=A,B,C` for a nested cascade
                       (top A → for each, top B → for each, top C).
      cardinality    — distinct value count ("unique" — how many different values)
      sum/avg/min/max — numeric stats
      stats          — all four at once
      percentiles    — 50/75/95/99
      histogram      — numeric buckets of given bucket_size
      date_histogram — time buckets of given interval (1h/1d/etc.)

    sub_card: comma-separated field names; for terms agg, adds a cardinality
    sub-agg per top-level bucket (e.g. group by host, count distinct users).
    """
    import urllib.error

    from services.elasticsearch import _request as es_req

    fields_list = [f.strip() for f in field.split(",") if f.strip()] if agg == "terms" else [field]
    if not fields_list:
        raise HTTPException(status_code=400, detail="field is required")
    sub_card_list = [s.strip() for s in sub_card.split(",") if s.strip()] if sub_card else []

    # Auto-route text fields to .keyword for terms aggs. Cache the probe per field.
    type_cache: dict[str, str] = {}

    def probe_type(f: str) -> str:
        if f in type_cache:
            return type_cache[f]
        try:
            mp = es_req("GET", f"/fo-case-{case_id}-*/_mapping/field/{f}")
            for _, body in (mp or {}).items():
                m = body.get("mappings", {}).get(f, {}).get("mapping", {})
                if m:
                    leaf = next(iter(m.values()))
                    ft = leaf.get("type") if isinstance(leaf, dict) else None
                    if ft:
                        type_cache[f] = ft
                        return ft
        except Exception:
            pass
        type_cache[f] = ""
        return ""

    def route(f: str) -> str:
        if f.endswith(".keyword"):
            return f
        ft = probe_type(f)
        if ft == "text":
            return f + ".keyword"
        return f

    # First-level resolved field (used for the response label)
    agg_field = route(fields_list[0]) if agg == "terms" else fields_list[0]
    if agg != "terms" and not agg_field.endswith(".keyword"):
        ft = probe_type(agg_field)
        # cardinality on text → use .keyword
        if ft == "text" and agg in ("cardinality",):
            agg_field = agg_field + ".keyword"

    # Validate agg vs field type BEFORE hitting ES, so the analyst gets a clear
    # 400 instead of a cryptic mapper error (e.g. running avg on a text field).
    _agg_err = agg_rules.validate_agg(agg, probe_type(agg_field))
    if _agg_err:
        raise HTTPException(status_code=400, detail=f"{_agg_err} (field '{agg_field}')")

    must = (
        [
            {
                "query_string": {
                    "query": q,
                    "default_operator": "AND",
                    "fields": ["*"],
                    "analyze_wildcard": True,
                }
            }
        ]
        if q
        else [{"match_all": {}}]
    )

    if agg == "terms":
        # Build nested terms aggs from right to left (innermost first)
        def build_terms_chain(idx: int) -> dict:
            f_resolved = route(fields_list[idx])
            term_opts: dict = {"field": f_resolved, "size": size}
            # A string 'missing' placeholder only makes sense for string-y
            # fields; on an ip/numeric/date field ES rejects it
            # ("'__missing__' is not an IP string literal"). Probe and gate.
            if agg_rules.terms_missing_supported(probe_type(f_resolved)):
                term_opts["missing"] = agg_rules.MISSING_PLACEHOLDER
            node = {"terms": term_opts}
            children: dict = {}
            if idx + 1 < len(fields_list):
                children["next"] = build_terms_chain(idx + 1)
            for sub_f in sub_card_list:
                sub_resolved = route(sub_f)
                children[f"card__{sub_f}"] = {"cardinality": {"field": sub_resolved}}
            if children:
                node["aggs"] = children
            return node

        aggs = {"out": build_terms_chain(0)}
    elif agg in ("sum", "avg", "min", "max"):
        aggs = {"out": {agg: {"field": agg_field}}}
    elif agg == "cardinality":
        aggs = {"out": {"cardinality": {"field": agg_field}}}
    elif agg == "stats":
        aggs = {"out": {"stats": {"field": agg_field}}}
    elif agg == "percentiles":
        aggs = {"out": {"percentiles": {"field": agg_field, "percents": [50, 75, 95, 99]}}}
    elif agg == "histogram":
        aggs = {
            "out": {"histogram": {"field": agg_field, "interval": bucket_size, "min_doc_count": 1}}
        }
    elif agg == "date_histogram":
        aggs = {
            "out": {
                "date_histogram": {
                    "field": agg_field,
                    "fixed_interval": interval,
                    "min_doc_count": 1,
                }
            }
        }
    else:
        raise HTTPException(status_code=400, detail=f"Unknown agg type: {agg}")

    # ES-side soft timeout → returns partial buckets + timed_out flag instead of
    # blowing the HTTP timeout and hard-failing. track_total_hits=True gives the
    # real query hit count (not the misleading 10k cap).
    body = {"size": 0, "query": {"bool": {"must": must}}, "aggs": aggs,
            "timeout": "25s", "track_total_hits": True}

    try:
        result = es_req("POST", f"/fo-case-{case_id}-*/_search", body)
    except urllib.error.HTTPError as exc:
        # Surface ES's actual error message — gives the analyst something useful
        try:
            import json as _json

            err_body = _json.loads(exc.read() or b"{}")
            reason = (
                err_body.get("error", {}).get("root_cause", [{}])[0].get("reason")
                or err_body.get("error", {}).get("reason")
                or str(exc)
            )
        except Exception:
            reason = str(exc)
        raise HTTPException(status_code=400, detail=reason)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    try:
        out = (result.get("aggregations") or {}).get("out") or {}
        total = result.get("hits", {}).get("total", {}).get("value", 0)
        timed_out = bool(result.get("timed_out"))
        # Normalize response shapes
        if agg == "terms":

            def walk(node):
                items = []
                for b in node.get("buckets", []):
                    item = {"value": b["key"], "count": b["doc_count"]}
                    # cardinality sub-aggs
                    for k, v in b.items():
                        if isinstance(v, dict) and k.startswith("card__"):
                            item.setdefault("uniques", {})[k.replace("card__", "")] = v.get(
                                "value", 0
                            )
                    # nested terms cascade
                    if isinstance(b.get("next"), dict):
                        item["children"] = walk(b["next"])
                    items.append(item)
                return items

            buckets = walk(out)
            return {
                "agg": agg,
                "field": agg_field,
                "fields": fields_list,
                "sub_card_fields": sub_card_list,
                "buckets": buckets,
                "total": total,
                "timed_out": timed_out,
                "sum_other_doc_count": out.get("sum_other_doc_count", 0),
            }
        if agg in ("histogram", "date_histogram"):
            buckets = [
                {"key": b.get("key_as_string", b["key"]), "count": b["doc_count"]}
                for b in out.get("buckets", [])
            ]
            return {"agg": agg, "field": agg_field, "buckets": buckets, "total": total}
        if agg == "stats":
            return {
                "agg": agg,
                "field": agg_field,
                "total": total,
                **{k: out.get(k) for k in ("count", "min", "max", "avg", "sum")},
            }
        if agg == "percentiles":
            return {"agg": agg, "field": agg_field, "total": total, "values": out.get("values", {})}
        # sum/avg/min/max/cardinality → scalar in out.value
        return {"agg": agg, "field": agg_field, "total": total, "value": out.get("value")}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/whois/{ip}")
def whois_lookup(ip: str):
    """RDAP/WHOIS lookup for an IP address via rdap.org."""
    import ipaddress as _ipaddr
    import json as _json
    import urllib.error as _err
    import urllib.request as _req

    try:
        addr = _ipaddr.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
    ):
        kind = (
            "Loopback"
            if addr.is_loopback
            else "Link-local"
            if addr.is_link_local
            else "Multicast"
            if addr.is_multicast
            else "Reserved"
            if addr.is_reserved
            else "Private"
        )
        return {
            "ip": ip,
            "org": f"{kind} / RFC-reserved",
            "country": "—",
            "cidr": "—",
            "handle": "—",
            "description": "Private, loopback, link-local, or reserved address space.",
        }

    url = f"https://rdap.org/ip/{ip}"
    try:
        request = _req.Request(url, headers={"Accept": "application/rdap+json, application/json"})
        with _req.urlopen(request, timeout=8) as resp:
            data = _json.loads(resp.read())
    except _err.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"RDAP lookup failed: HTTP {exc.code}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"RDAP lookup: {exc}")

    # CIDR from start/end address range
    cidr = ""
    start_addr = data.get("startAddress", "")
    end_addr = data.get("endAddress", "")
    if start_addr and end_addr:
        try:
            nets = list(
                _ipaddr.summarize_address_range(
                    _ipaddr.ip_address(start_addr),
                    _ipaddr.ip_address(end_addr),
                )
            )
            cidr = ", ".join(str(n) for n in nets[:4])
        except Exception:
            cidr = f"{start_addr} – {end_addr}"

    # Org name from registrant/administrative vCard
    org = data.get("name", "")
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if not any(r in roles for r in ("registrant", "administrative")):
            continue
        vcard = entity.get("vcardArray", [])
        if len(vcard) > 1:
            for prop in vcard[1]:
                if isinstance(prop, list) and prop and prop[0] == "fn":
                    fn = prop[3] if len(prop) > 3 else ""
                    if fn:
                        org = fn
                        break

    # First remark description
    description = ""
    for remark in data.get("remarks", []):
        if isinstance(remark, dict):
            desc_list = remark.get("description", [])
            if isinstance(desc_list, list) and desc_list:
                description = desc_list[0]
                break

    return {
        "ip": ip,
        "org": org,
        "country": data.get("country", "—"),
        "cidr": cidr or data.get("handle", "—"),
        "handle": data.get("handle", "—"),
        "description": description,
    }
