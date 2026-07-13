"""Tests for baseline/stacking pure logic (compute_rare) + field allowlist."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.baseline import compute_rare, is_allowed_field  # noqa: E402


def _b(key, host_count, on_target, total=None):
    return {
        "key": key,
        "doc_count": total if total is not None else on_target,
        "host_count": {"value": host_count},
        "on_target": {"doc_count": on_target},
    }


def test_keeps_only_rare_and_on_target():
    buckets = [
        _b("svchost.exe", 50, 10),  # common — dropped
        _b("evil.exe", 1, 3),  # rare + on target — keep
        _b("other.exe", 1, 0),  # rare but NOT on target — dropped
    ]
    out = compute_rare(buckets, max_hosts=2)
    assert [r["value"] for r in out] == ["evil.exe"]
    assert out[0]["host_count"] == 1
    assert out[0]["target_count"] == 3


def test_sorted_rarest_first():
    buckets = [
        _b("a", 2, 5),
        _b("b", 1, 9),
        _b("c", 1, 2),
    ]
    out = compute_rare(buckets, max_hosts=2)
    # host_count asc, then target_count asc → c(1,2), b(1,9), a(2,5)
    assert [r["value"] for r in out] == ["c", "b", "a"]


def test_max_hosts_threshold_inclusive():
    buckets = [_b("x", 3, 1), _b("y", 2, 1)]
    out = compute_rare(buckets, max_hosts=2)
    assert [r["value"] for r in out] == ["y"]  # 3 > 2 dropped, 2 <= 2 kept


def test_unique_to_target_flag_and_priority():
    buckets = [
        _b("shared.exe", 2, 4),  # on 2 hosts — rare but NOT unique to target
        _b("only-here.exe", 1, 1),  # on 1 host (the target) — unique
    ]
    out = compute_rare(buckets, max_hosts=2)
    # unique-to-target ranks first even though it has fewer target hits.
    assert [r["value"] for r in out] == ["only-here.exe", "shared.exe"]
    assert out[0]["unique_to_target"] is True
    assert out[1]["unique_to_target"] is False


def test_rarity_score_when_total_hosts_given():
    buckets = [_b("evil.exe", 1, 3), _b("semi.exe", 5, 3)]
    out = compute_rare(buckets, max_hosts=10, total_hosts=100)
    by_val = {r["value"]: r for r in out}
    assert by_val["evil.exe"]["rarity"] == 0.99  # 1 - 1/100
    assert by_val["semi.exe"]["rarity"] == 0.95  # 1 - 5/100


def test_no_rarity_key_without_total_hosts():
    out = compute_rare([_b("x", 1, 1)], max_hosts=2)
    assert "rarity" not in out[0]


def test_empty():
    assert compute_rare([], 2) == []


def test_field_allowlist():
    assert is_allowed_field("process.name.keyword") is True
    assert is_allowed_field("password") is False
    assert is_allowed_field("") is False
