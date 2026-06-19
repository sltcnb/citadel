#!/usr/bin/env python3
"""
Offline unit tests for Talon's stability hardening:

  • execution log is created and tees output (survives a crash/kill)
  • disk-space helpers report free space and format byte counts
  • the empty-archive guard refuses to upload a 0-file (~22-byte) ZIP

No collection of real artifacts here — we exercise the packaging /
guard / logging plumbing directly.

Run:
    pytest tools/talon/tests/test_stability.py
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collect  # noqa: E402


def test_fmt_bytes():
    assert collect._fmt_bytes(0) == "0.0 B"
    assert collect._fmt_bytes(1024) == "1.0 KB"
    assert collect._fmt_bytes(1024 * 1024) == "1.0 MB"
    assert collect._fmt_bytes(5 * 1024**3).endswith("GB")


def test_disk_free_walks_to_existing_parent(tmp_path):
    # A path several levels below an existing dir still resolves free space.
    deep = tmp_path / "a" / "b" / "c" / "out.zip"
    info = collect._disk_free(deep)
    assert info is not None
    free, total = info
    assert free > 0 and total >= free


def test_execution_log_tees_and_closes(tmp_path):
    out = tmp_path / "out.zip"
    log_path = collect._setup_execution_log(out)
    try:
        assert log_path is not None and log_path.exists()
        print("hello-from-collector")
        sys.stderr.write("warn-from-collector\n")
    finally:
        collect._close_execution_log()
    text = log_path.read_text(encoding="utf-8")
    assert "hello-from-collector" in text
    assert "warn-from-collector" in text
    # restore streams for the rest of the suite
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__


def test_empty_package_is_22_byte_stub(tmp_path):
    """An archive with zero items is the ~22-byte end-of-central-directory stub
    — exactly the artifact the empty-guard must refuse to upload."""
    c = collect.Collector.__new__(collect.Collector)
    c.output = tmp_path / "empty.zip"
    c.staging = tmp_path / "staging"
    c.staging.mkdir()
    c._items = []
    c._errors = []
    c.package()
    assert c.output.exists()
    assert c.output.stat().st_size <= 22
    assert len(c._items) == 0  # guard keys off this in main()


def test_package_writes_collected_files(tmp_path):
    src = tmp_path / "evidence.txt"
    src.write_text("artifact-bytes")
    c = collect.Collector.__new__(collect.Collector)
    c.output = tmp_path / "bundle.zip"
    c.staging = tmp_path / "staging"
    c.staging.mkdir()
    c._items = [("evidence.txt", src)]
    c._errors = []
    c.package()
    assert not getattr(c, "_disk_full", False)
    with zipfile.ZipFile(c.output) as zf:
        assert zf.namelist() == ["evidence.txt"]
        assert zf.read("evidence.txt") == b"artifact-bytes"


if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-v"]))
