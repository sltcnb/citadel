"""Silent-evidence-drop regression tests for routers/ingest.py.

Empty files and nested archives used to be dropped with only a server log
line; the ingest response must now carry per-file skip reasons in its
``errors`` list. Handlers are called directly (api/ colocated-test convention)
— no FastAPI app boot; the job service is monkeypatched.
"""

import sys
import zipfile
from pathlib import Path

import pytest
from fastapi import BackgroundTasks

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import routers.ingest as ing  # noqa: E402


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setattr(ing.job_svc, "create_job", lambda *a, **k: {})
    monkeypatch.setattr(ing.job_svc, "update_job", lambda *a, **k: None)


def test_empty_file_skip_surfaced_in_errors(env, tmp_path):
    p = tmp_path / "empty.evtx"
    p.write_bytes(b"")
    dispatched: list = []
    errors: list = []

    ing._ingest_one_async("c1", "empty.evtx", str(p), 0, dispatched, errors, BackgroundTasks())

    assert dispatched == []
    assert len(errors) == 1
    assert errors[0]["filename"] == "empty.evtx"
    assert "Empty file" in errors[0]["error"]
    assert not p.exists()  # temp file cleaned up


def test_empty_auxiliary_file_stays_silent(env, tmp_path):
    """Auxiliary sidecar files (sqlite WAL/SHM) are empty by design — no error."""
    p = tmp_path / "evidence.sqlite-wal"
    p.write_bytes(b"")
    dispatched: list = []
    errors: list = []

    ing._ingest_one_async(
        "c1", "evidence.sqlite-wal", str(p), 0, dispatched, errors, BackgroundTasks()
    )

    assert dispatched == []
    assert errors == []


def test_nested_zip_skip_surfaced_per_archive(env, tmp_path):
    zp = tmp_path / "outer.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("inner.zip", b"PK\x05\x06" + b"\x00" * 18)  # empty zip bytes
        zf.writestr("logs/real.log", b"some log line\n")
    dispatched: list = []
    errors: list = []

    ing._handle_zip_async("c1", "outer.zip", str(zp), dispatched, errors, BackgroundTasks())

    # The real entry is dispatched…
    assert [d["filename"] for d in dispatched] == ["logs/real.log"]
    # …and the nested archive drop is surfaced, naming the skipped entry.
    notes = [e for e in errors if e["filename"] == "outer.zip"]
    assert len(notes) == 1
    assert "nested archive" in notes[0]["error"]
    assert "inner.zip" in notes[0]["error"]


def test_zip_with_only_nested_zips_reports_note_not_generic_error(env, tmp_path):
    zp = tmp_path / "only_nested.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("a.zip", b"PK\x05\x06" + b"\x00" * 18)
    dispatched: list = []
    errors: list = []

    ing._handle_zip_async("c1", "only_nested.zip", str(zp), dispatched, errors, BackgroundTasks())

    assert dispatched == []
    assert len(errors) == 1
    assert "nested archive" in errors[0]["error"]
    assert "a.zip" in errors[0]["error"]
