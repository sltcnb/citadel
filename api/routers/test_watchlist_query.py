"""Watchlist query-builder tests — the ``hash`` kind must match file hash
fields (file.sha256/sha1/md5 per the fo-cases index template), not just
process.hash_*."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routers.watchlist import _build_query  # noqa: E402


def test_hash_kind_matches_process_and_file_fields():
    q = _build_query("hash", "d41d8cd98f00b204e9800998ecf8427e")
    for field in (
        "process.hash_md5",
        "process.hash_sha1",
        "process.hash_sha256",
        "file.md5",
        "file.sha1",
        "file.sha256",
    ):
        assert f'{field}:"d41d8cd98f00b204e9800998ecf8427e"' in q


def test_hash_kind_empty_value_builds_nothing():
    assert _build_query("hash", "   ") == ""
