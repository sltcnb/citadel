"""Tests for agg_rules — the ip/__missing__ aggregation bug and type validation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agg_rules as ar  # noqa: E402


def test_string_missing_only_for_stringy_fields():
    # The exact bug: a string 'missing' placeholder on an ip field is illegal.
    assert ar.terms_missing_supported("ip") is False
    assert ar.terms_missing_supported("long") is False
    assert ar.terms_missing_supported("date") is False
    assert ar.terms_missing_supported("boolean") is False
    # String-y fields are fine.
    assert ar.terms_missing_supported("keyword") is True
    assert ar.terms_missing_supported("text") is True
    assert ar.terms_missing_supported("") is True  # unknown → permissive


def test_numeric_agg_rejected_on_text():
    err = ar.validate_agg("avg", "text")
    assert err and "numeric" in err.lower()
    assert ar.validate_agg("sum", "keyword")
    assert ar.validate_agg("histogram", "ip")


def test_numeric_agg_allowed_on_numeric_and_date():
    assert ar.validate_agg("avg", "long") is None
    assert ar.validate_agg("sum", "double") is None
    assert ar.validate_agg("min", "date") is None  # date supports min/max
    assert ar.validate_agg("percentiles", "scaled_float") is None


def test_date_histogram_requires_date():
    assert ar.validate_agg("date_histogram", "long")  # error
    assert ar.validate_agg("date_histogram", "date") is None


def test_terms_and_cardinality_unconstrained_by_numeric_rule():
    # terms/cardinality are valid on any type (text routed to .keyword elsewhere)
    assert ar.validate_agg("terms", "ip") is None
    assert ar.validate_agg("cardinality", "keyword") is None


def test_unknown_field_type_is_permissive():
    assert ar.validate_agg("avg", "") is None  # don't block an un-probed field


if __name__ == "__main__":
    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        globals()[name]()
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
