"""Reports must read the SAME notes store the UI writes.

The notes editor (routers/notes.py) and archive export use the
``fo:notes:{case_id}`` hash (``rk.case_notes``), but the report builder used to
read the legacy ``case:{case_id}:notes`` string key — so UI-written notes never
appeared in any report, and template-seeded notes (written to the legacy key)
were invisible in the editor. These tests pin the unified store.
"""

from __future__ import annotations

import sys
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("scribe", reason="report rendering engine not installed")

import redis_keys as rk  # noqa: E402

import routers.case_templates as ct  # noqa: E402
import routers.notes as notes  # noqa: E402
import routers.reports as rp  # noqa: E402


@pytest.fixture
def fake(monkeypatch):
    client = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(rp, "get_redis", lambda: client)
    monkeypatch.setattr(notes, "_r", lambda: client)
    monkeypatch.setattr(ct, "get_redis", lambda: client)
    return client


def test_ui_written_notes_appear_in_report_data(fake):
    notes.save_notes("c1", notes.NoteIn(body="host master2 was wiped"))
    assert rp._fetch_notes("c1") == "host master2 was wiped"


def test_report_data_carries_ui_notes(fake):
    fake.hset(rk.case_notes("c1"), mapping={"body": "timeline gap 02:00-04:00", "updated_at": "t"})
    data = rp._build_report_data({"case_id": "c1", "name": "C1"}, "c1")
    assert data["notes"] == "timeline gap 02:00-04:00"


def test_template_notes_seed_the_shared_hash(fake):
    out = ct.apply_template("c1", template_id="ransomware", case={"case_id": "c1"})
    assert out["notes_seeded"] is True
    body = fake.hget(rk.case_notes("c1"), "body")
    assert body                       # stored in the shared hash…
    assert notes.get_notes("c1")["body"] == body   # …visible in the editor…
    assert rp._fetch_notes("c1") == body           # …and in reports
    assert fake.get("case:c1:notes") is None       # legacy key no longer written


def test_template_notes_do_not_overwrite_existing(fake):
    notes.save_notes("c1", notes.NoteIn(body="analyst work in progress"))
    out = ct.apply_template("c1", template_id="ransomware", case={"case_id": "c1"})
    assert out["notes_seeded"] is False
    assert rp._fetch_notes("c1") == "analyst work in progress"
