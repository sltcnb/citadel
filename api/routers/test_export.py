"""Unit tests for routers/export.py — evidence-integrity paths.

Follows the api/ colocated-test convention: no FastAPI app boot, handlers and
helpers called directly, fakeredis for Redis, es_req / urllib monkeypatched.

Focus: exported data must faithfully match the source events — no field loss,
correct CSV escaping, one valid JSON object per NDJSON line — and archive
import/bulk-indexing must not mutate events beyond the documented case_id
rewrite. Secrets in archive settings must never be echoed back to clients.
"""

import asyncio
import csv
import gzip
import io
import json
import sys
import tarfile
from pathlib import Path

import fakeredis
import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import redis_keys as rk  # noqa: E402
import routers.export as ex  # noqa: E402


def _drain(resp) -> bytes:
    """Consume a StreamingResponse's body synchronously."""

    async def _run():
        chunks = []
        async for c in resp.body_iterator:
            chunks.append(c.encode() if isinstance(c, str) else c)
        return b"".join(chunks)

    return asyncio.run(_run())


@pytest.fixture
def export_redis(monkeypatch):
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(ex, "get_redis", lambda: fake, raising=True)
    return fake


# ── Pure helpers ──────────────────────────────────────────────────────────────


def test_strip_http():
    assert ex._strip_http("https://s3.example.com:9000") == "s3.example.com:9000"
    assert ex._strip_http("http://minio:9000") == "minio:9000"
    assert ex._strip_http("HTTPS://UP.example.com") == "UP.example.com"
    assert ex._strip_http("minio:9000") == "minio:9000"


def test_flatten_doc_preserves_all_non_raw_leaves():
    doc = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": {"hostname": "WS01", "os": {"name": "Windows", "version": "10"}},
        "tags": ["a", "b"],
        "raw": "BULKY BLOB",  # top-level raw* is deliberately dropped
        "raw_data": {"x": 1},
        "process": {"raw_title": "kept — prefix is process., not raw"},
    }
    flat = ex._flatten_doc(doc)
    assert flat == {
        "timestamp": "2026-01-01T00:00:00Z",
        "host.hostname": "WS01",
        "host.os.name": "Windows",
        "host.os.version": "10",
        "tags": ["a", "b"],
        "process.raw_title": "kept — prefix is process., not raw",
    }
    assert ex._flatten_doc({}) == {}
    assert ex._flatten_doc(None) == {}


def test_csv_cell_rendering():
    assert ex._csv_cell(None) == ""
    assert ex._csv_cell(["10.0.0.1", "10.0.0.2"]) == "10.0.0.1, 10.0.0.2"
    assert ex._csv_cell({"k": "vé"}) == '{"k": "vé"}'  # ensure_ascii=False
    assert ex._csv_cell(42) == "42"
    assert ex._csv_cell(True) == "True"
    assert ex._csv_cell('a,"b"\nc') == 'a,"b"\nc'  # escaping is csv.writer's job


# ── CSV export (round-trip fidelity) ──────────────────────────────────────────

DOC1 = {
    "timestamp": "2026-01-01T10:00:00Z",
    "artifact_type": "evtx",
    "message": 'comma, "quote" and\nnewline é€',
    "host": {"hostname": "WS01", "ip": ["10.0.0.1", "10.0.0.2"]},
    "user": {"name": "alice"},
    "process": {"name": "powershell.exe", "command_line": "powershell -enc Zm9v"},
    "tags": ["t1", "t2"],
    "raw": "MUST NOT APPEAR",
}
DOC2 = {
    "timestamp": "2026-01-02T11:00:00Z",
    "artifact_type": "evtx",
    "message": "second",
    "nested": {"deep": {"leaf": 7}},
}


def _fake_es(sample_docs, scroll_docs, deleted):
    """es_req stub: sample search, one scroll page, then empty + DELETE."""

    def fake(method, path, body=None):
        if method == "DELETE":
            deleted.append(body)
            return {}
        if "scroll=2m" in path:
            return {
                "_scroll_id": "sc1",
                "hits": {"hits": [{"_source": d} for d in scroll_docs]},
            }
        if path == "/_search/scroll":
            return {"_scroll_id": "sc1", "hits": {"hits": []}}
        # column-discovery sample
        return {"hits": {"hits": [{"_source": d} for d in sample_docs]}}

    return fake


def test_export_csv_roundtrip_no_field_loss(monkeypatch):
    deleted: list = []
    monkeypatch.setattr(ex, "es_req", _fake_es([DOC1, DOC2], [DOC1, DOC2], deleted), raising=True)

    resp = ex.export_csv("caseabcdef12")
    text = _drain(resp).decode("utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    header, data = rows[0], rows[1:]

    # Preferred columns come first, in the canonical order; raw is dropped.
    assert header[: header.index("host.hostname") + 1][0] == "timestamp"
    assert "raw" not in header
    assert header[-1] == "_extra"
    preferred_present = [c for c in ex._CSV_PREFERRED if c in header]
    assert header[: len(preferred_present)] == preferred_present

    assert len(data) == 2
    r1 = dict(zip(header, data[0]))
    # CSV escaping round-trips the hostile message byte-for-byte.
    assert r1["message"] == DOC1["message"]
    assert r1["host.hostname"] == "WS01"
    assert r1["host.ip"] == "10.0.0.1, 10.0.0.2"
    assert r1["user.name"] == "alice"
    assert r1["process.command_line"] == "powershell -enc Zm9v"
    assert r1["tags"] == "t1, t2"
    assert r1["_extra"] == ""
    r2 = dict(zip(header, data[1]))
    assert r2["nested.deep.leaf"] == "7"
    assert r2["user.name"] == ""  # absent field → empty cell, not an error

    # Every non-raw input leaf appears somewhere in the export (no field loss).
    for doc in (DOC1, DOC2):
        for key in ex._flatten_doc(doc):
            assert key in header

    assert deleted == [{"scroll_id": "sc1"}]  # scroll context cleaned up
    assert resp.headers["content-disposition"] == "attachment; filename=case-caseabcd-all.csv"


def test_export_csv_unsampled_fields_land_in_extra(monkeypatch):
    surprise = {**DOC2, "surprise": {"k": "v"}}
    monkeypatch.setattr(ex, "es_req", _fake_es([DOC2], [surprise], []), raising=True)
    rows = list(csv.reader(io.StringIO(_drain(ex.export_csv("c1")).decode())))
    header, row = rows[0], dict(zip(rows[0], rows[1]))
    assert "surprise.k" not in header  # not in the sample → not a column
    assert json.loads(row["_extra"]) == {"surprise.k": "v"}  # ...but never lost


def test_scroll_query_paginates_and_cleans_up(monkeypatch):
    pages = [
        {"_scroll_id": "s1", "hits": {"hits": [{"_source": {"n": 1}}, {"_source": {"n": 2}}]}},
        {"_scroll_id": "s2", "hits": {"hits": [{"_source": {"n": 3}}]}},
        {"_scroll_id": "s3", "hits": {"hits": []}},
    ]
    calls: list = []

    def fake(method, path, body=None):
        calls.append((method, path, body))
        if method == "DELETE":
            return {}
        return pages.pop(0)

    monkeypatch.setattr(ex, "es_req", fake, raising=True)
    docs = list(ex._scroll_query("fo-case-x-*", {"match_all": {}}))
    assert docs == [{"n": 1}, {"n": 2}, {"n": 3}]
    assert calls[-1] == ("DELETE", "/_search/scroll", {"scroll_id": "s3"})


# ── Bulk indexing (import path) ───────────────────────────────────────────────


def _gz_ndjson(events) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        for e in events:
            gz.write((json.dumps(e) if isinstance(e, dict) else e).encode() + b"\n")
    return buf.getvalue()


class _FakeBulkResp:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _capture_bulk(monkeypatch, payload=None):
    bodies: list[bytes] = []

    def fake_urlopen(req, timeout=None):
        bodies.append(req.data)
        return _FakeBulkResp(payload or {"errors": False, "items": []})

    monkeypatch.setattr(ex.urllib.request, "urlopen", fake_urlopen, raising=True)
    return bodies


def test_bulk_index_events_faithful_and_routed(monkeypatch):
    events = [
        {"timestamp": "t1", "artifact_type": "evtx", "message": "a", "case_id": "OLD"},
        {"timestamp": "t2", "artifact_type": "mft", "path": "C:\\x,y\n"},
        {"timestamp": "t3", "message": "no type"},
    ]
    bodies = _capture_bulk(monkeypatch)
    count = ex._bulk_index_events("newcase", _gz_ndjson(events))
    assert count == 3

    lines = b"".join(bodies).decode().strip().splitlines()
    assert len(lines) == 6  # action+doc pair per event
    actions = [json.loads(lines[i]) for i in range(0, 6, 2)]
    docs = [json.loads(lines[i]) for i in range(1, 6, 2)]
    assert [a["index"]["_index"] for a in actions] == [
        "fo-case-newcase-evtx",
        "fo-case-newcase-mft",
        "fo-case-newcase-unknown",  # missing artifact_type routed to 'unknown'
    ]
    # Docs are byte-faithful apart from the documented case_id rewrite.
    for original, indexed in zip(events, docs):
        assert indexed == {**original, "case_id": "newcase"}


def test_bulk_index_skips_blank_and_malformed_lines(monkeypatch):
    payload = _gz_ndjson(
        [
            {"artifact_type": "evtx", "m": 1},
            "",  # blank line
            "{not json",  # malformed line
            {"artifact_type": "evtx", "m": 2},
        ]
    )
    bodies = _capture_bulk(monkeypatch)
    assert ex._bulk_index_events("c", payload) == 2
    lines = b"".join(bodies).decode().strip().splitlines()
    assert len(lines) == 4  # only the two valid events made it


def test_bulk_index_counts_per_item_failures(monkeypatch):
    resp = {
        "errors": True,
        "items": [
            {"index": {"status": 201}},
            {"index": {"status": 400, "error": {"type": "mapper_parsing_exception"}}},
            {"index": {"status": 201}},
        ],
    }
    _capture_bulk(monkeypatch, payload=resp)
    events = [{"artifact_type": "evtx", "n": i} for i in range(3)]
    assert ex._bulk_index_events("c", _gz_ndjson(events)) == 2  # 3 sent - 1 rejected


# ── .citadel archive build (export fidelity) ──────────────────────────────────

CASE = {
    "case_id": "case77",
    "name": "Acme Breach",
    "status": "active",
    "analyst": "nb",
    "created_at": "2026-06-01T00:00:00+00:00",
}
JOBS = [{"job_id": "j1", "sha256": "aa" * 32, "original_filename": "triage.zip"}]
EVENTS = [
    {"timestamp": "t1", "artifact_type": "evtx", "message": 'é "quoted"\nline'},
    {"timestamp": "t2", "artifact_type": "mft", "path": "C:\\Users\\bob"},
]


@pytest.fixture
def archive_env(export_redis, monkeypatch):
    monkeypatch.setattr(ex, "get_case", lambda cid: CASE if cid == "case77" else None, raising=True)
    monkeypatch.setattr(ex.job_svc, "list_case_job_ids", lambda cid: ["j1"], raising=True)
    monkeypatch.setattr(ex.job_svc, "get_job", lambda jid: JOBS[0] if jid == "j1" else None, raising=True)
    monkeypatch.setattr(ex, "_scroll_all_events", lambda cid: iter(EVENTS), raising=True)
    export_redis.hset(rk.case_notes("case77"), mapping={"body": "notes here", "updated_at": "t"})
    export_redis.set(rk.case_alert_rules("case77"), json.dumps([{"rule": "r1"}]))
    return export_redis


def test_build_archive_members_and_event_fidelity(archive_env, tmp_path):
    out = tmp_path / "case.citadel"
    assert ex._build_archive("case77", str(out)) == len(EVENTS)

    with tarfile.open(out, "r:gz") as tf:
        names = set(tf.getnames())
        assert names == {
            "case.json",
            "jobs.json",
            "notes.json",
            "alert_rules.json",
            "saved_searches.json",
            "events.ndjson.gz",
            "manifest.json",
        }

        def read(n):
            return tf.extractfile(tf.getmember(n)).read()

        assert json.loads(read("case.json")) == CASE
        assert json.loads(read("jobs.json")) == JOBS
        assert json.loads(read("notes.json"))["body"] == "notes here"
        assert json.loads(read("alert_rules.json")) == [{"rule": "r1"}]
        assert json.loads(read("saved_searches.json")) == []

        manifest = json.loads(read("manifest.json"))
        assert manifest["format"] == ex.ARCHIVE_FORMAT
        assert manifest["case_id"] == "case77"
        assert manifest["event_count"] == len(EVENTS)
        assert manifest["job_count"] == 1

        # Every NDJSON line is standalone-valid JSON and events round-trip exactly.
        lines = gzip.decompress(read("events.ndjson.gz")).decode("utf-8").splitlines()
        assert [json.loads(line) for line in lines] == EVENTS


def test_export_archive_404_and_filename_sanitized(archive_env, monkeypatch):
    with pytest.raises(HTTPException) as exc:
        ex.export_archive("nope")
    assert exc.value.status_code == 404

    monkeypatch.setattr(
        ex, "get_case", lambda cid: {**CASE, "name": "Ransom: ACME/../x"}, raising=True
    )
    resp = ex.export_archive("case77")
    disp = resp.headers["content-disposition"]
    assert disp == 'attachment; filename="case-Ransom__ACME____x.citadel"'
    body = _drain(resp)  # also deletes the temp file
    # The streamed body is the archive itself — readable end to end.
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tf:
        assert "manifest.json" in tf.getnames()


def test_export_then_import_roundtrip(archive_env, tmp_path, monkeypatch):
    """Full-circle evidence integrity: build the archive, import it back, and
    check the re-indexed events equal the originals (modulo case_id rewrite)."""
    out = tmp_path / "case.citadel"
    ex._build_archive("case77", str(out))

    bodies = _capture_bulk(monkeypatch)
    result = ex._import_archive_file(str(out))

    new_cid = result["case_id"]
    assert new_cid and new_cid != "case77"
    assert result["original_case_id"] == "case77"
    assert result["events_imported"] == len(EVENTS)
    assert result["jobs_restored"] == 1

    # Case restored in Redis with the original name.
    assert archive_env.hget(f"case:{new_cid}", "name") == "Acme Breach"
    assert archive_env.sismember("cases:all", new_cid)
    assert archive_env.hget(f"case:{new_cid}", "case_id") == new_cid

    # Re-indexed docs match the exported events exactly (plus new case_id).
    lines = b"".join(bodies).decode().strip().splitlines()
    docs = [json.loads(lines[i]) for i in range(1, len(lines), 2)]
    assert docs == [{**e, "case_id": new_cid} for e in EVENTS]


def test_import_rejects_non_archive(tmp_path):
    bogus = tmp_path / "bogus.tar.gz"
    with tarfile.open(bogus, "w:gz") as tf:
        info = tarfile.TarInfo("random.txt")
        info.size = 2
        tf.addfile(info, io.BytesIO(b"hi"))
    with pytest.raises(HTTPException) as exc:
        ex._import_archive_file(str(bogus))
    assert exc.value.status_code == 400  # missing manifest.json


# ── Archive settings: secret handling ─────────────────────────────────────────


def test_archive_settings_secret_never_echoed_and_preserved(export_redis):
    body = ex.ArchiveSettingsIn(
        s3_endpoint="https://s3.example.com",
        s3_access_key="AK",
        s3_secret_key="topsecret",
        s3_bucket="archives",
    )
    out = ex.update_archive_settings(body)
    assert "s3_secret_key" not in out  # never echoed back
    assert out["s3_secret_key_set"] is True
    assert out["s3_endpoint"] == "https://s3.example.com"

    # Re-save with an empty secret → the stored secret must be preserved.
    out2 = ex.update_archive_settings(
        ex.ArchiveSettingsIn(
            s3_endpoint="https://s3.example.com",
            s3_access_key="AK",
            s3_secret_key="",
            s3_bucket="archives-2",
        )
    )
    assert out2["s3_bucket"] == "archives-2"
    assert out2["s3_secret_key_set"] is True
    stored = json.loads(export_redis.get(rk.ARCHIVE_SETTINGS))
    assert stored["s3_secret_key"] == "topsecret"
