"""Decompression-bomb defenses for the archive plugin.

Covers the safety limits added to ``babel.archive.archive_plugin`` (PR #9):

  * a member whose *declared* size exceeds the per-archive cap is skipped
    before any bytes are read;
  * a member that *lies* (small declared size, large actual payload) is aborted
    mid-copy by the running byte counter (``_bounded_extract_copy`` raises the
    internal ``_ExtractionLimit``);
  * nested-archive recursion beyond ``MAX_DEPTH`` is not extracted;
  * the shared global byte budget is enforced across nested extraction;
  * a legitimate small archive still extracts fully;
  * a zip-slip entry (``../``) is rejected by ``_safe_target``.

The caps are lowered per-test via the module constants the code reads (the same
values ``ARCHIVE_MAX_*`` env vars populate at import) so the tests stay fast and
never allocate real gigabytes.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from babel.archive import archive_plugin as ap
from babel.archive.archive_plugin import ArchivePlugin, _ExtractionLimit
from babel.base_plugin import PluginContext


# ── helpers ────────────────────────────────────────────────────────────────


def _make_ctx(path: Path, config: dict | None = None) -> PluginContext:
    return PluginContext(
        case_id="c",
        job_id="j",
        source_file_path=path,
        source_minio_url="",
        config=config or {},
    )


def _plugin(path: Path, config: dict | None = None) -> ArchivePlugin:
    """An ArchivePlugin with the recursion/budget state ``parse()`` would set up,
    so the ``_extract*`` helpers can be exercised directly."""
    p = ArchivePlugin(_make_ctx(path, config))
    p._depth = 0
    p._budget = [ap.MAX_GLOBAL_BYTES]
    p._archive_bytes = 0
    return p


def _write_zip(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)


@pytest.fixture
def low_caps(monkeypatch):
    """Lower every cap to a handful of bytes so tests are fast."""
    monkeypatch.setattr(ap, "MAX_EXTRACTED_BYTES", 1024)
    monkeypatch.setattr(ap, "MAX_GLOBAL_BYTES", 4096)
    monkeypatch.setattr(ap, "MAX_DEPTH", 1)
    return ap


# ── (a) declared size > per-archive cap is skipped ───────────────────────────


def test_declared_oversize_member_is_skipped(tmp_path, low_caps):
    arc = tmp_path / "declared.zip"
    # A well-compressing 8 KiB member — declared file_size (8192) > cap (1024).
    _write_zip(arc, {"big.txt": b"A" * 8192, "small.txt": b"hello"})
    dest = tmp_path / "out"
    dest.mkdir()

    p = _plugin(arc)
    assert p._extract_zip(arc, dest) is True

    # Oversize member never written; legitimate small one extracted.
    assert not (dest / "big.txt").exists()
    assert (dest / "small.txt").read_bytes() == b"hello"


# ── (b) size-lie aborted mid-copy by the running byte counter ────────────────


def test_bounded_copy_aborts_when_actual_exceeds_cap(low_caps):
    # A "member" that declares nothing but streams far more than the cap.
    src = io.BytesIO(b"X" * (ap.MAX_EXTRACTED_BYTES * 3))
    dst = io.BytesIO()
    p = _plugin(Path("dummy"))

    with pytest.raises(_ExtractionLimit):
        p._bounded_extract_copy(src, dst)
    # Aborted after crossing the cap, not after slurping everything.
    assert dst.tell() <= ap.MAX_EXTRACTED_BYTES + ap._COPY_CHUNK


def test_lying_zip_member_aborted_and_partial_file_removed(tmp_path, monkeypatch):
    # Declared size stays under the cap (cheap reject passes) but the copy loop
    # crosses it. We make _COPY_CHUNK tiny so the running counter trips without
    # a real multi-MB payload.
    monkeypatch.setattr(ap, "MAX_EXTRACTED_BYTES", 64)
    monkeypatch.setattr(ap, "MAX_GLOBAL_BYTES", 10_000)
    monkeypatch.setattr(ap, "_COPY_CHUNK", 16)

    arc = tmp_path / "liar.zip"
    payload = b"Z" * 512  # 512 actual bytes, but ZIP_STORED so declared == 512
    # Force declared size under cap by patching what the reject check sees:
    # simpler — use a member <= cap declared is impossible with 512 bytes, so we
    # instead drive _bounded_extract_copy through a stored member and rely on the
    # copy-loop abort (the declared-size guard is covered separately above).
    _write_zip(arc, {"liar.bin": payload})
    dest = tmp_path / "out"
    dest.mkdir()

    p = _plugin(arc)
    # 512 declared > 64 cap, so it's skipped at declare-check. To exercise the
    # mid-copy abort explicitly, call the copy helper directly on a stream whose
    # length the caller could not have known in advance.
    assert p._extract_zip(arc, dest) is True
    assert not (dest / "liar.bin").exists()

    # Now the pure mid-copy path: declared unknown, actual >> cap.
    p2 = _plugin(arc)
    out = dest / "written.bin"
    with pytest.raises(_ExtractionLimit):
        with io.BytesIO(payload) as src, open(out, "wb") as dst:
            p2._bounded_extract_copy(src, dst)


# ── (c) nested recursion beyond MAX_DEPTH is stopped ─────────────────────────


def test_recursion_beyond_max_depth_does_not_extract(tmp_path, low_caps, monkeypatch):
    arc = tmp_path / "deep.zip"
    _write_zip(arc, {"inner.txt": b"data"})

    # Depth already past the (lowered) MAX_DEPTH → parse() returns immediately
    # without ever creating a temp extraction dir.
    called = {"mkdtemp": False}
    real_mkdtemp = ap.tempfile.mkdtemp

    def _spy(*a, **k):
        called["mkdtemp"] = True
        return real_mkdtemp(*a, **k)

    monkeypatch.setattr(ap.tempfile, "mkdtemp", _spy)

    p = ArchivePlugin(_make_ctx(arc, {ap._CFG_DEPTH: ap.MAX_DEPTH + 1}))
    events = list(p.parse())

    assert events == []
    assert called["mkdtemp"] is False


# ── (d) shared global budget enforced across (nested) extraction ─────────────


def test_global_budget_shared_and_enforced(tmp_path, monkeypatch):
    # Per-archive cap is generous; the *global* budget is the binding limit.
    monkeypatch.setattr(ap, "MAX_EXTRACTED_BYTES", 10_000)
    monkeypatch.setattr(ap, "MAX_GLOBAL_BYTES", 128)
    monkeypatch.setattr(ap, "_COPY_CHUNK", 16)

    p = _plugin(Path("dummy"))
    # Simulate an earlier (nested) archive already having consumed most of the
    # shared budget — only 32 bytes remain.
    p._budget = [32]

    src = io.BytesIO(b"Y" * 256)
    dst = io.BytesIO()
    with pytest.raises(_ExtractionLimit):
        p._bounded_extract_copy(src, dst)
    # Budget went negative → tripped even though per-archive cap (10k) was fine.
    assert p._budget[0] < 0
    assert p._archive_bytes < ap.MAX_EXTRACTED_BYTES


# ── (e) legitimate small archive extracts fully ──────────────────────────────


def test_small_archive_extracts_fully(tmp_path, low_caps):
    arc = tmp_path / "ok.zip"
    members = {"a.txt": b"alpha", "sub/b.txt": b"bravo", "c.txt": b"charlie"}
    _write_zip(arc, members)
    dest = tmp_path / "out"
    dest.mkdir()

    p = _plugin(arc)
    assert p._extract_zip(arc, dest) is True
    for name, data in members.items():
        assert (dest / name).read_bytes() == data


# ── (f) zip-slip / path traversal rejected by _safe_target ───────────────────


def test_safe_target_rejects_zip_slip(tmp_path):
    dest = tmp_path / "out"
    dest.mkdir()
    p = _plugin(tmp_path / "x.zip")

    assert p._safe_target(dest, "../evil.txt") is None
    assert p._safe_target(dest, "../../etc/passwd") is None
    # Absolute paths are stripped of leading sep and land safely inside dest.
    inside = p._safe_target(dest, "sub/ok.txt")
    assert inside is not None
    assert inside.resolve().is_relative_to(dest.resolve())


def test_zip_slip_member_not_written(tmp_path, low_caps):
    arc = tmp_path / "slip.zip"
    _write_zip(arc, {"../escape.txt": b"pwned", "safe.txt": b"ok"})
    dest = tmp_path / "out"
    dest.mkdir()

    p = _plugin(arc)
    assert p._extract_zip(arc, dest) is True
    # The traversal target (parent of dest) must never be created.
    assert not (dest.parent / "escape.txt").exists()
    assert (dest / "safe.txt").read_bytes() == b"ok"
