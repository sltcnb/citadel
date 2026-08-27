"""Executable skills for the Pilot agent.

A playbook is prose the model reads and may ignore. A skill is a procedure it
calls by name: deterministic, parameterised, and correct the same way every
time. The difference matters most for the things a DFIR analyst does
constantly and an LLM does badly by improvisation.

IOC matching is the clearest case. Asked to check a domain and an IP against a
case, a real run issued::

    message:*dntds* OR message:*178.16.53.137*

Three things are wrong with that and all three are fatal. A leading wildcard
scans every term in the index. ``message`` is a rendered summary, so an
indicator that only ever appears in a structured field — ``network.dst_ip``,
``browser.url`` — is invisible to it. And the indicator was never defanged, so
``dntds[.]shop`` would not have matched ``dntds.shop`` anyway. The run reported
"0 results" and treated it as absence of evidence.

The knowledge needed to do it properly — defang the indicator, classify it,
then query the fields that type actually lives in — is fixed, small, and
belongs in code. :func:`ioc_sweep` is that knowledge.

Everything that decides *what to ask* is a pure function here and is tested
without Elasticsearch. Only the runners touch the index, through an injected
``search`` callable, so a skill can be exercised end to end against a stub.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# ── Indicator normalisation ───────────────────────────────────────────────────

# Analysts and intel feeds hand over defanged indicators as a matter of course,
# so an IOC tool that only accepts live ones is wrong by default.
_DEFANG_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\[\.\]", "."),      # dntds[.]shop
    (r"\(\.\)", "."),      # dntds(.)shop
    (r"\{\.\}", "."),      # dntds{.}shop
    (r"\[dot\]", "."),     # dntds[dot]shop
    (r"\[:\]", ":"),       # hxxp[:]//
    (r"\[@\]", "@"),       # user[@]example.com
    (r"\[at\]", "@"),
    (r"^h(?:xx|XX)p", "http"),   # hxxp:// and hxxps://
)

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]{3,}:[0-9a-fA-F:]*$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,63}$")


def defang(raw: str) -> str:
    """Turn a defanged indicator back into its live form.

    ``dntds[.]shop`` → ``dntds.shop``; ``hxxps://x[.]com`` → ``https://x.com``.
    Idempotent, so a live indicator passes through untouched.
    """
    out = (raw or "").strip().strip("\"'`<>,;")
    for pattern, repl in _DEFANG_PATTERNS:
        out = re.sub(pattern, repl, out, flags=re.IGNORECASE)
    return out


def classify(value: str) -> str:
    """Indicator type: ipv4 | ipv6 | sha256 | sha1 | md5 | email | url | domain | unknown.

    Order matters — a bare 32-hex string is a hash, not a domain, and a URL is
    checked before its host would be mistaken for one.
    """
    v = (value or "").strip()
    if not v:
        return "unknown"
    if _IPV4_RE.match(v):
        # Reject 999.1.1.1 rather than issue a query that can never match.
        return "ipv4" if all(0 <= int(o) <= 255 for o in v.split(".")) else "unknown"
    if _SHA256_RE.match(v):
        return "sha256"
    if _SHA1_RE.match(v):
        return "sha1"
    if _MD5_RE.match(v):
        return "md5"
    if _URL_RE.match(v):
        return "url"
    if _EMAIL_RE.match(v):
        return "email"
    if ":" in v and _IPV6_RE.match(v):
        return "ipv6"
    if _DOMAIN_RE.match(v):
        return "domain"
    return "unknown"


# ── Field targeting ───────────────────────────────────────────────────────────
#
# Where each indicator type actually lives, taken from what the parsers emit
# rather than from what ECS says they might. Exact fields are matched exactly;
# free-text fields need a substring match because the indicator is embedded in
# a longer value (a domain inside a URL, an IP inside a log line).

_EXACT_FIELDS: dict[str, tuple[str, ...]] = {
    "ipv4": (
        "network.src_ip",
        "network.dst_ip",
        "network.remote_ip",
        "network.local_ip",
        "source.ip",
        "destination.ip",
    ),
    "ipv6": (
        "network.src_ip",
        "network.dst_ip",
        "network.remote_ip",
        "network.local_ip",
        "source.ip",
        "destination.ip",
    ),
    "sha256": ("file.sha256", "process.sha256", "hash.sha256"),
    "sha1": ("file.sha1", "process.sha1", "hash.sha1"),
    "md5": ("file.md5", "process.md5", "hash.md5"),
    "domain": ("dns.question.name", "network.domain", "host.hostname"),
    "email": ("user.email", "email.from", "email.to"),
    "url": ("browser.url", "browser.referrer"),
}

_SUBSTRING_FIELDS: dict[str, tuple[str, ...]] = {
    # A domain is embedded in a URL and in log text, so exact match alone
    # misses the browser history and the DNS log line that name it.
    "domain": ("browser.url", "browser.referrer", "message"),
    "url": ("message",),
    "ipv4": ("message",),
    "ipv6": ("message",),
    "sha256": ("message",),
    "sha1": ("message",),
    "md5": ("message",),
    "email": ("message",),
    "unknown": ("message",),
}


def _escape_term(value: str) -> str:
    """Escape Lucene metacharacters in a literal indicator."""
    return re.sub(r'([+\-!(){}\[\]^"~*?:\\/])', r"\\\1", value)


def build_ioc_query(value: str, kind: str) -> str:
    """The query for one indicator: exact where the field is exact, substring
    where the indicator is embedded in a longer value.

    Returns a Lucene query string targeting real fields, never a bare
    ``message:*term*`` — which is both slow and blind to structured data.
    """
    esc = _escape_term(value)
    clauses = [f"{f}:{esc}" for f in _EXACT_FIELDS.get(kind, ())]
    # Wildcards must not be escaped away, so the substring form uses the raw
    # value with only quotes stripped.
    inner = value.replace('"', "")
    clauses += [f"{f}:*{inner}*" for f in _SUBSTRING_FIELDS.get(kind, ("message",))]
    return " OR ".join(clauses)


# ── Skill registry ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Skill:
    id: str
    summary: str
    params: str


SKILLS: tuple[Skill, ...] = (
    Skill(
        id="ioc_sweep",
        summary=(
            "Check indicators against the case the right way: defang them, "
            "classify each, and query the fields that type actually lives in. "
            "Use this INSTEAD of hand-written message:*term* searches."
        ),
        params='{"action":"ioc_sweep","indicators":["dntds[.]shop","178.16.53.137"]}',
    ),
    Skill(
        id="host_profile",
        summary=(
            "One-call orientation on a host: which artifact types it has, its "
            "users, its time span and event count. Run this before searching a "
            "host so you know what evidence exists."
        ),
        params='{"action":"host_profile","host":"L20336"}',
    ),
)

SKILLS_BY_ID: dict[str, Skill] = {s.id: s for s in SKILLS}


def skills_block() -> str:
    """Prompt fragment advertising the skills."""
    lines = ["\nSkills — prefer these over hand-built queries:"]
    for s in SKILLS:
        lines.append(f"  {s.id:14s} {s.summary}")
        lines.append(f"  {'':14s} e.g. {s.params}")
    return "\n".join(lines) + "\n"


# ── Runners ───────────────────────────────────────────────────────────────────
#
# `search` is injected: (query: str, size: int) -> dict with keys
# {"total": int, "hits": [{"fo_id","message","artifact_type"}]}. Keeping the
# index access behind a callable is what lets the whole skill be tested.

SearchFn = Callable[[str, int], dict]


def run_ioc_sweep(
    indicators: list[str],
    search: SearchFn,
    *,
    per_indicator_samples: int = 3,
) -> dict:
    """Sweep each indicator against the case and report per-indicator results."""
    if not indicators:
        return {
            "query_status": "invalid",
            "query_error": 'ioc_sweep needs indicators: {"indicators":["evil.com","1.2.3.4"]}',
        }

    results: list[dict] = []
    seen: set[str] = set()
    for raw in indicators[:40]:
        if not isinstance(raw, str) or not raw.strip():
            continue
        value = defang(raw)
        if value.lower() in seen:
            continue
        seen.add(value.lower())
        kind = classify(value)
        entry: dict[str, Any] = {"raw": raw, "value": value, "type": kind}

        if kind == "unknown":
            # Still worth a text sweep — an unparseable indicator may be a
            # mutex, a filename or a registry key — but say it was not typed,
            # so a miss is not read as a clean negative.
            entry["note"] = (
                "not recognised as an ip/domain/url/hash/email — swept as free text only"
            )

        query = build_ioc_query(value, kind)
        entry["query"] = query
        try:
            res = search(query, per_indicator_samples)
        except Exception as exc:  # noqa: BLE001 — one bad indicator must not kill the sweep
            entry["error"] = str(exc)[:200]
            entry["hits"] = None
            results.append(entry)
            continue

        total = int(res.get("total") or 0)
        entry["hits"] = total
        entry["sample"] = [
            {
                "fo_id": h.get("fo_id"),
                "artifact_type": h.get("artifact_type"),
                "message": (h.get("message") or "")[:200],
            }
            for h in (res.get("hits") or [])[:per_indicator_samples]
        ]
        results.append(entry)

    matched = [r for r in results if (r.get("hits") or 0) > 0]
    clean = [r for r in results if r.get("hits") == 0]
    errored = [r for r in results if r.get("error")]

    out: dict[str, Any] = {
        "query_status": "ok",
        "indicators": results,
        "matched": len(matched),
        "clean": len(clean),
        "errors": len(errored),
        "result_count": sum(r.get("hits") or 0 for r in results),
    }
    if matched:
        out["note"] = (
            f"{len(matched)} indicator(s) present in this case: "
            + ", ".join(r["value"] for r in matched)
        )
    elif clean and not errored:
        # The distinction the original run got wrong.
        out["note"] = (
            "No indicator matched. This is a clean sweep of the fields these "
            "indicator types live in — but it is only meaningful for artifact "
            "types the case actually contains. Check the specialist plan before "
            "reporting this as absence of compromise."
        )
    return out


def run_host_profile(host: str, search: SearchFn, aggregate) -> dict:
    """What evidence exists for one host, in a single call.

    Orientation is the step agents skip and then pay for: the run that closed
    "inconclusive" had never established that its only host held one artifact
    type. Four aggregates answer that, so make it one action.
    """
    host = (host or "").strip()
    if not host:
        return {"query_status": "invalid", "query_error": 'host_profile needs {"host":"NAME"}'}

    scope = f'host.hostname:"{host}"'
    profile: dict[str, Any] = {"query_status": "ok", "host": host}
    try:
        base = search(scope, 1)
        profile["event_count"] = int(base.get("total") or 0)
    except Exception as exc:  # noqa: BLE001
        return {"query_status": "invalid", "query_error": str(exc)[:200]}

    if profile["event_count"] == 0:
        profile["note"] = (
            f"No events carry host.hostname:{host}. The name may be spelled "
            "differently in the data, or host.hostname may be unpopulated for "
            "these artifact types — aggregate host.hostname.keyword to see the "
            "real values before concluding the host is absent."
        )
        return profile

    for label, field in (
        ("artifact_types", "artifact_type.keyword"),
        ("users", "user.name.keyword"),
        ("processes", "process.name.keyword"),
    ):
        try:
            profile[label] = aggregate(field, scope, 12)
        except Exception:  # noqa: BLE001 — a missing field is not a failed profile
            profile[label] = []

    types = profile.get("artifact_types") or []
    if len(types) <= 1:
        profile["note"] = (
            f"This host has only {len(types) or 'no'} artifact type(s). Most "
            "investigative questions cannot be answered from that — treat it as "
            "a collection gap and say so, rather than searching for evidence "
            "that was never collected."
        )
    return profile
