"""Regression tests: artifact_type must never escape the caller's case prefix.

ES treats a comma in the request path as a multi-index list, so a raw
artifact_type like "x,fo-case-<victim>-*" turned timeline/search/facets/CSV
into a cross-tenant event read. build_index_expression validates and
re-anchors every part with the caller's own case prefix.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.elasticsearch import build_index_expression  # noqa: E402


def test_plain_artifact_type():
    assert build_index_expression("abc123", "evtx") == "fo-case-abc123-evtx"


def test_empty_means_wildcard():
    assert build_index_expression("abc123", None) == "fo-case-abc123-*"
    assert build_index_expression("abc123", "") == "fo-case-abc123-*"
    assert build_index_expression("abc123", "*") == "fo-case-abc123-*"


def test_comma_list_is_reanchored_per_part():
    # Legit multi-type filters keep working — but each part gets the caller's
    # own case prefix, never a smuggled one.
    assert (
        build_index_expression("abc123", "evtx, prefetch")
        == "fo-case-abc123-evtx,fo-case-abc123-prefetch"
    )


def test_multi_index_injection_rejected():
    # The exact cross-tenant payload from the audit.
    with pytest.raises(ValueError):
        build_index_expression("abc123", "zzz,fo-case-victim99-evtx")


@pytest.mark.parametrize("bad", ["evtx*", "../x", "a b", "EVTX", "fo-case-x-y", "-evtx", "."])
def test_malformed_values_rejected(bad):
    with pytest.raises(ValueError):
        build_index_expression("abc123", bad)
