"""Full-text search: plain terms are case-insensitive substring matches across
every field (search_all), field queries keep Lucene semantics, and a case
mid-migration answers from both paths instead of dropping the old indices."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from services import elasticsearch as es  # noqa: E402


def wc(v):
    return {"wildcard": {"search_all": {"value": v, "case_insensitive": True}}}


def test_bare_word_is_a_substring():
    assert es.plain_terms_query("kalmo") == {"bool": {"must": [wc("*kalmo*")]}}


def test_user_wildcards_and_quotes_are_respected():
    assert es.plain_terms_query("*veeam*") == {"bool": {"must": [wc("*veeam*")]}}
    assert es.plain_terms_query("sa_vee*") == {"bool": {"must": [wc("sa_vee*")]}}
    assert es.plain_terms_query('*"ShareWriteable"*') == {"bool": {"must": [wc("*ShareWriteable*")]}}
    assert es.plain_terms_query('"logon success"') == {"bool": {"must": [wc("*logon success*")]}}


def test_windows_paths_and_times_stay_plain_with_literal_backslashes():
    assert es.plain_terms_query(r"C:\Windows\Temp") == {"bool": {"must": [wc(r"*C:\\Windows\\Temp*")]}}
    assert es.plain_terms_query("08:04:14") == {"bool": {"must": [wc("*08:04:14*")]}}
    assert es.plain_terms_query("192.168.100") == {"bool": {"must": [wc("*192.168.100*")]}}


def test_boolean_operators():
    q = es.plain_terms_query("veeam AND 4624 NOT svc -bob")
    assert q == {"bool": {"must": [wc("*veeam*"), wc("*4624*")], "must_not": [wc("*svc*"), wc("*bob*")]}}
    q = es.plain_terms_query("tmirt OR wmiprvse")
    assert q == {"bool": {"should": [{"bool": {"must": [wc("*tmirt*")]}}, {"bool": {"must": [wc("*wmiprvse*")]}}],
                          "minimum_should_match": 1}}


def test_field_queries_and_complex_expressions_keep_lucene():
    for q in ("user.name:bob", "evtx.event_id:4624 AND veeam", "(a OR b) AND c",
              "timestamp:[2026-01-01 TO 2026-01-02]", "/ab+c/", '"unbalanced'):
        assert es.plain_terms_query(q) is None, q


def test_search_all_indices_reads_field_caps(monkeypatch):
    es._SEARCH_ALL_CACHE.clear()
    monkeypatch.setattr(es, "_request", lambda m, p, b: {
        "indices": ["fo-case-c-evtx", "fo-case-c-mft"],
        "fields": {"search_all": {"keyword": {"type": "keyword", "indices": ["fo-case-c-mft"]},
                                  "unmapped": {"type": "unmapped", "indices": ["fo-case-c-evtx"]}}}})
    assert es.search_all_indices("fo-case-c-*") == ({"fo-case-c-mft"}, {"fo-case-c-evtx"})
    es._SEARCH_ALL_CACHE.clear()
    monkeypatch.setattr(es, "_request", lambda m, p, b: {
        "indices": ["fo-case-d-evtx"], "fields": {"search_all": {"keyword": {"type": "keyword"}}}})
    assert es.search_all_indices("fo-case-d-*") == ({"fo-case-d-evtx"}, set())
    es._SEARCH_ALL_CACHE.clear()
    monkeypatch.setattr(es, "_request", lambda m, p, b: {"indices": ["fo-case-e-evtx"], "fields": {}})
    assert es.search_all_indices("fo-case-e-*") == (set(), {"fo-case-e-evtx"})


def _capture(monkeypatch, upgraded, legacy):
    sent = {}
    monkeypatch.setattr(es, "search_all_indices", lambda idx: (set(upgraded), set(legacy)))

    def fake(method, path, body):
        sent["body"] = body
        return {"hits": {"total": {"value": 0}, "hits": []}}

    monkeypatch.setattr(es, "_request", fake)
    return sent


def test_upgraded_case_uses_only_search_all(monkeypatch):
    sent = _capture(monkeypatch, ["fo-case-c-evtx"], [])
    r = es.search_events("c", "tmirt")
    assert r["search_scope"] == "all-fields"
    assert "query_string" not in str(sent["body"]["query"]) and "*tmirt*" in str(sent["body"]["query"])


def test_mixed_case_routes_each_index_to_its_path(monkeypatch):
    sent = _capture(monkeypatch, ["fo-case-c-mft"], ["fo-case-c-evtx"])
    r = es.search_events("c", "tmirt")
    q = str(sent["body"]["query"])
    assert r["search_scope"] == "mixed"
    assert "fo-case-c-mft" in q and "fo-case-c-evtx" in q and "query_string" in q and "search_all" in q


def test_legacy_case_and_field_queries_keep_the_old_path(monkeypatch):
    sent = _capture(monkeypatch, [], ["fo-case-c-evtx"])
    assert es.search_events("c", "tmirt")["search_scope"] == "core-fields"
    sent = _capture(monkeypatch, ["fo-case-c-evtx"], [])
    r = es.search_events("c", "user.name:bob")
    assert "query_string" in str(sent["body"]["query"]) and "search_all" not in str(sent["body"]["query"])
    assert r["search_scope"] == "lucene"  # no "incomplete" banner for a field query
