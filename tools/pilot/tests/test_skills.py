"""Pilot skills — the executable procedures, as opposed to the playbooks' prose.

The IOC skill exists because of a specific failure. Asked to check a domain and
an IP against a case, a real run issued

    message:*dntds* OR message:*178.16.53.137*

and reported 0 results as absence of evidence. That query is wrong three ways:
a leading wildcard scans every term in the index; ``message`` is a rendered
summary, so an indicator living only in ``network.dst_ip`` or ``browser.url``
is invisible to it; and the indicator was never defanged, so ``dntds[.]shop``
could not have matched ``dntds.shop`` regardless.

These tests pin all three.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pilot.skills import (  # noqa: E402
    SKILLS,
    SKILLS_BY_ID,
    build_ioc_query,
    classify,
    defang,
    run_host_profile,
    run_ioc_sweep,
    skills_block,
)

# ── Defanging ─────────────────────────────────────────────────────────────────


def test_defangs_the_forms_intel_feeds_actually_use():
    assert defang("dntds[.]shop") == "dntds.shop"
    assert defang("dntds(.)shop") == "dntds.shop"
    assert defang("dntds{.}shop") == "dntds.shop"
    assert defang("dntds[dot]shop") == "dntds.shop"
    assert defang("hxxp://evil.com") == "http://evil.com"
    assert defang("hxxps://evil.com") == "https://evil.com"
    assert defang("hxxps://evil[.]com") == "https://evil.com"
    assert defang("user[@]example.com") == "user@example.com"
    assert defang("1.2.3[.]4") == "1.2.3.4"


def test_defang_is_idempotent_on_live_indicators():
    for live in ("dntds.shop", "178.16.53.137", "https://evil.com/a"):
        assert defang(live) == live
        assert defang(defang(live)) == live


def test_defang_strips_surrounding_punctuation():
    assert defang('  "dntds[.]shop",  ') == "dntds.shop"
    assert defang("<178.16.53.137>") == "178.16.53.137"


# ── Classification ────────────────────────────────────────────────────────────


def test_classifies_each_indicator_type():
    assert classify("178.16.53.137") == "ipv4"
    assert classify("dntds.shop") == "domain"
    assert classify("https://dntds.shop/x") == "url"
    assert classify("a" * 64) == "sha256"
    assert classify("b" * 40) == "sha1"
    assert classify("c" * 32) == "md5"
    assert classify("user@example.com") == "email"
    assert classify("2001:db8::1") == "ipv6"


def test_a_bare_hash_is_not_read_as_a_domain():
    """32 hex characters is an md5, and querying it as a hostname finds nothing."""
    assert classify("d41d8cd98f00b204e9800998ecf8427e") == "md5"


def test_impossible_ipv4_is_rejected_rather_than_queried():
    """999.1.1.1 can never match; issuing the query wastes a step."""
    assert classify("999.1.1.1") == "unknown"
    assert classify("178.16.53.137") == "ipv4"


def test_unparseable_indicator_is_unknown_not_guessed():
    assert classify("") == "unknown"
    assert classify("Global\\SomeMutexName") == "unknown"


# ── Query construction ────────────────────────────────────────────────────────


def test_ip_query_targets_the_structured_ip_fields():
    q = build_ioc_query("178.16.53.137", "ipv4")
    for f in ("network.src_ip", "network.dst_ip", "network.remote_ip"):
        assert f"{f}:178.16.53.137" in q


def test_domain_query_covers_both_exact_and_embedded_positions():
    """A domain is exact in dns.question.name and embedded inside a URL."""
    q = build_ioc_query("dntds.shop", "domain")
    assert "dns.question.name:dntds.shop" in q
    assert "browser.url:*dntds.shop*" in q
    assert "browser.referrer:*dntds.shop*" in q


def test_hash_query_targets_hash_fields():
    q = build_ioc_query("a" * 64, "sha256")
    assert "file.sha256:" in q
    assert "process.sha256:" in q


def test_query_is_never_message_only():
    """The regression: message-only search is blind to structured fields."""
    for value, kind in (
        ("178.16.53.137", "ipv4"),
        ("dntds.shop", "domain"),
        ("a" * 32, "md5"),
    ):
        q = build_ioc_query(value, kind)
        clauses = [c.strip() for c in q.split(" OR ")]
        non_message = [c for c in clauses if not c.startswith("message:")]
        assert non_message, f"{kind} query hits only message: {q}"


def test_lucene_metacharacters_in_an_indicator_are_escaped():
    """An unescaped indicator can turn into a syntax error, or worse, a query
    that silently means something else."""
    q = build_ioc_query("evil.com/a+b", "url")
    assert "\\+" in q


# ── The sweep ─────────────────────────────────────────────────────────────────

# A case where each indicator exists ONLY in a structured field — precisely
# where the original message:* search could not see it.
_CORPUS = [
    {
        "fo_id": "e1",
        "artifact_type": "browser",
        "message": "[3x] Free Mac Cleaner",
        "browser.url": "https://dntds.shop/download",
    },
    {
        "fo_id": "e2",
        "artifact_type": "network_conn",
        "message": "tcp4 192.168.1.10:52344 ESTABLISHED",
        "network.dst_ip": "178.16.53.137",
    },
    {"fo_id": "e3", "artifact_type": "syslog", "message": "ASL Sender Statistics"},
]


def _stub_search(query, size):
    hits = []
    for doc in _CORPUS:
        for clause in query.split(" OR "):
            field, _, term = clause.partition(":")
            term = term.strip().strip("*").replace("\\", "")
            if field.strip() in doc and term and term in str(doc[field.strip()]):
                hits.append(doc)
                break
    return {"total": len(hits), "hits": hits[:size]}


def test_sweep_finds_indicators_held_only_in_structured_fields():
    r = run_ioc_sweep(["dntds[.]shop", "178.16.53.137"], _stub_search)
    assert r["query_status"] == "ok"
    assert r["matched"] == 2
    assert r["clean"] == 0
    by_value = {i["value"]: i for i in r["indicators"]}
    assert by_value["dntds.shop"]["sample"][0]["artifact_type"] == "browser"
    assert by_value["178.16.53.137"]["sample"][0]["artifact_type"] == "network_conn"


def test_sweep_reports_each_indicator_separately():
    """One aggregate "0 results" hides which indicator was clean and which was
    never queried properly."""
    r = run_ioc_sweep(["dntds[.]shop", "notpresent.example"], _stub_search)
    assert r["matched"] == 1
    assert r["clean"] == 1
    hits = {i["value"]: i["hits"] for i in r["indicators"]}
    assert hits["dntds.shop"] == 1
    assert hits["notpresent.example"] == 0


def test_clean_sweep_is_qualified_not_declared_innocent():
    r = run_ioc_sweep(["nothing.example"], _stub_search)
    assert r["matched"] == 0
    assert "absence of compromise" in r["note"]
    assert "specialist plan" in r["note"]


def test_sweep_requires_indicators():
    r = run_ioc_sweep([], _stub_search)
    assert r["query_status"] == "invalid"


def test_sweep_deduplicates_after_defanging():
    """"evil[.]com" and "evil.com" are one indicator, not two searches."""
    r = run_ioc_sweep(["evil[.]com", "evil.com", "EVIL.COM"], _stub_search)
    assert len(r["indicators"]) == 1


def test_one_failing_indicator_does_not_kill_the_sweep():
    calls = {"n": 0}

    def flaky(query, size):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("index unavailable")
        return _stub_search(query, size)

    r = run_ioc_sweep(["first.example", "dntds[.]shop"], flaky)
    assert r["errors"] == 1
    assert r["matched"] == 1


def test_unknown_indicator_is_swept_but_flagged():
    """A miss on an untyped indicator must not read as a clean negative."""
    r = run_ioc_sweep(["Global\\SomeMutex"], _stub_search)
    entry = r["indicators"][0]
    assert entry["type"] == "unknown"
    assert "free text only" in entry["note"]


# ── host_profile ──────────────────────────────────────────────────────────────


def test_host_profile_flags_a_host_with_one_artifact_type():
    """The orientation the failing run never did: its only host held one type,
    which makes most questions unanswerable."""

    def search(query, size):
        return {"total": 45, "hits": []}

    def aggregate(field, query, size):
        return ["syslog"] if field.startswith("artifact_type") else []

    p = run_host_profile("L20336", search, aggregate)
    assert p["event_count"] == 45
    assert p["artifact_types"] == ["syslog"]
    assert "collection gap" in p["note"]


def test_host_profile_on_unknown_host_suggests_checking_the_field():
    """host.hostname is unpopulated for many artifact types, so zero hits does
    not mean the host is absent."""

    def search(query, size):
        return {"total": 0, "hits": []}

    p = run_host_profile("NOPE", search, lambda *a: [])
    assert p["event_count"] == 0
    assert "host.hostname may be unpopulated" in p["note"]


def test_host_profile_requires_a_host():
    assert run_host_profile("", lambda *a: {}, lambda *a: [])["query_status"] == "invalid"


def test_host_profile_survives_a_missing_aggregate_field():
    def search(query, size):
        return {"total": 10, "hits": []}

    def aggregate(field, query, size):
        raise RuntimeError("no such field")

    p = run_host_profile("WS01", search, aggregate)
    assert p["query_status"] == "ok"
    assert p["artifact_types"] == []


# ── Registry ──────────────────────────────────────────────────────────────────


def test_every_skill_documents_itself_for_the_prompt():
    for s in SKILLS:
        assert s.summary.strip(), s.id
        assert s.params.strip().startswith("{"), s.id
        assert s.id in s.params, s.id
    assert set(SKILLS_BY_ID) == {s.id for s in SKILLS}


def test_skills_block_tells_the_agent_to_prefer_them():
    block = skills_block()
    assert "ioc_sweep" in block
    assert "host_profile" in block
    assert "hand-built queries" in block
