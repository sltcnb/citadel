"""Aggregation field-type rules — pure, dependency-free, unit-testable.

Centralises the Elasticsearch aggregation/field-type compatibility logic so the
search router stays thin and the rules can be tested without ES or FastAPI.

Two questions this answers:
  * ``validate_agg(agg, field_type)`` — may this aggregation run on this field
    type? Returns a human-readable error string, or ``None`` if OK.
  * ``terms_missing_supported(field_type)`` — may a string ``missing`` bucket
    placeholder be attached? (False for ip/numeric/date/boolean, where a string
    placeholder makes ES throw e.g. "'__missing__' is not an IP string literal".)
"""

from __future__ import annotations

# Elasticsearch numeric field types eligible for sum/avg/min/max/stats/…
NUMERIC_ES_TYPES: frozenset[str] = frozenset(
    {
        "long",
        "integer",
        "short",
        "byte",
        "double",
        "float",
        "half_float",
        "scaled_float",
        "unsigned_long",
    }
)

# Aggregations that require a numeric (or date) field.
NUMERIC_AGGS: frozenset[str] = frozenset(
    {
        "sum",
        "avg",
        "min",
        "max",
        "stats",
        "percentiles",
        "histogram",
    }
)

# Field types on which a string `missing` bucket placeholder is valid.
_STRINGY = frozenset({"", "text", "keyword"})

MISSING_PLACEHOLDER = "__missing__"


def validate_agg(agg: str, field_type: str) -> str | None:
    """Return an error message if ``agg`` cannot run on ``field_type``, else None.

    An empty/unknown ``field_type`` is treated as permissive (let ES decide) so
    we never block on an un-probed field.
    """
    if not field_type:
        return None
    if agg in NUMERIC_AGGS and field_type not in NUMERIC_ES_TYPES and field_type != "date":
        return (
            f"Cannot run '{agg}' on a '{field_type}' field. "
            f"Numeric aggregations require a numeric field."
        )
    if agg == "date_histogram" and field_type != "date":
        return f"date_histogram requires a date field; this field is '{field_type}'."
    return None


def terms_missing_supported(field_type: str) -> bool:
    """True when a string ``missing`` placeholder may be attached to a terms agg."""
    return field_type in _STRINGY


def needs_keyword_subfield(agg: str, field_type: str) -> bool:
    """True when a text field must use its ``.keyword`` subfield for this agg."""
    return field_type == "text" and agg in ("terms", "cardinality")
