"""Search upgrade (index rebuild) — every interruption point must be lossless."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from services import search_upgrade as su  # noqa: E402

IDX = "fo-case-c1-evtx"
TMP = su.TMP_PREFIX + "c1-evtx"


class FakeES:
    """Indices as {name: {"docs": n, "search_all": bool}}; the fo-case-* template
    gives search_all to any index it creates."""

    def __init__(self, **indices):
        self.ix = {k: dict(v) for k, v in indices.items()}
        self.tasks = {}
        self.fail_reindex_into = None

    def __call__(self, method, path, body):
        p = path.split("?")[0].strip("/")
        if p.startswith("_index_template/_simulate_index/"):
            return {"template": {"settings": {"index": {"number_of_shards": "1"}}, "mappings": {"properties": {}}}}
        if p == "_reindex":
            src, dst = body["source"]["index"], body["dest"]["index"]
            n = self.ix[src]["docs"]
            if dst == self.fail_reindex_into:
                self.ix.setdefault(dst, {"docs": 0, "search_all": True})["docs"] = n // 2
                raise RuntimeError("killed mid-reindex")
            tgt = self.ix.setdefault(dst, {"docs": 0, "search_all": dst.startswith("fo-case-")})
            tgt["docs"] = n
            self.tasks["t1"] = n
            return {"task": "t1"}
        if p.startswith("_tasks/"):
            return {"completed": True, "response": {"total": self.tasks["t1"], "failures": []}}
        if p.startswith("_cat/indices/"):
            prefix = p[len("_cat/indices/"):].rstrip("*")
            return [{"index": k} for k in self.ix if k.startswith(prefix)]
        name, _, rest = p.partition("/")
        if method == "PUT" and not rest:
            self.ix[name] = {"docs": 0, "search_all": True}
            return {}
        if method == "DELETE":
            self.ix.pop(name)
            return {}
        if name not in self.ix:
            raise RuntimeError(f"no such index {name}")
        if rest == "_settings" or rest == "_refresh":
            return {}
        if rest == "_count":
            return {"count": self.ix[name]["docs"]}
        if rest == "_mapping/field/search_all":
            return {name: {"mappings": {"search_all": {}} if self.ix[name]["search_all"] else {}}}
        raise AssertionError(f"unexpected {method} {path}")


@pytest.fixture
def fake(monkeypatch):
    def make(**ix):
        es = FakeES(**ix)
        monkeypatch.setattr(su, "_request", es)
        monkeypatch.setattr(su.time, "sleep", lambda s: None)
        return es
    return make


def test_fresh_upgrade_rebuilds_with_search_all_and_cleans_up(fake):
    es = fake(**{IDX: {"docs": 500, "search_all": False}})
    assert su.upgrade_index(IDX, lambda m: None) == {"index": IDX, "docs": 500}
    assert es.ix == {IDX: {"docs": 500, "search_all": True}}


def test_resume_after_original_was_deleted(fake):
    es = fake(**{TMP: {"docs": 500, "search_all": True}})
    su.upgrade_index(IDX, lambda m: None)
    assert es.ix == {IDX: {"docs": 500, "search_all": True}}


def test_resume_after_a_partial_rebuild_never_trusts_the_partial_index(fake):
    es = fake(**{IDX: {"docs": 250, "search_all": True}, TMP: {"docs": 500, "search_all": True}})
    su.upgrade_index(IDX, lambda m: None)
    assert es.ix == {IDX: {"docs": 500, "search_all": True}}


def test_partial_copy_beside_an_intact_original_is_redone(fake):
    es = fake(**{IDX: {"docs": 500, "search_all": False}, TMP: {"docs": 120, "search_all": True}})
    su.upgrade_index(IDX, lambda m: None)
    assert es.ix == {IDX: {"docs": 500, "search_all": True}}


def test_leftover_copy_after_a_complete_rebuild_is_removed(fake):
    es = fake(**{IDX: {"docs": 500, "search_all": True}, TMP: {"docs": 500, "search_all": True}})
    su.upgrade_index(IDX, lambda m: None)
    assert es.ix == {IDX: {"docs": 500, "search_all": True}}


def test_failure_during_copy_keeps_the_original(fake):
    es = fake(**{IDX: {"docs": 500, "search_all": False}})
    es.fail_reindex_into = TMP
    with pytest.raises(RuntimeError):
        su.upgrade_index(IDX, lambda m: None)
    assert es.ix[IDX] == {"docs": 500, "search_all": False}


def test_failure_during_rebuild_keeps_the_copy_and_the_next_run_finishes(fake):
    es = fake(**{IDX: {"docs": 500, "search_all": False}})
    es.fail_reindex_into = IDX
    with pytest.raises(RuntimeError):
        su.upgrade_index(IDX, lambda m: None)
    assert es.ix[TMP]["docs"] == 500            # nothing lost
    es.fail_reindex_into = None
    su.upgrade_index(IDX, lambda m: None)
    assert es.ix == {IDX: {"docs": 500, "search_all": True}}


def test_upgrade_refused_while_ingest_is_in_flight(monkeypatch):
    monkeypatch.setattr(su, "active_ingest_jobs", lambda cid: 3)
    out = su.start_upgrade("c1")
    assert out["status"] == "refused" and "3 ingest job(s)" in out["reason"]
