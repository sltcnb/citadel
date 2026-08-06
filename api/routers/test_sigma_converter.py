"""Unit tests for the Sigma → Elasticsearch Lucene converter in global_alert_rules.

Pure functions (no Redis/ES) — they're the most complex untested logic on the
detection path, so they get the most direct coverage here: field mapping,
value modifiers, list-OR, and the supported `condition` expressions.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routers.global_alert_rules import (  # noqa: E402
    _map_field,
    _sigma_selection_to_es,
    _sigma_to_es_query,
    _sigma_value_to_es,
)


# ── Field mapping ────────────────────────────────────────────────────────────


def test_map_known_fields_case_insensitive():
    assert _map_field("CommandLine") == "process.command_line"
    assert _map_field("Image") == "process.path"
    assert _map_field("TargetUserName") == "user.name"
    assert _map_field("DestinationIp") == "network.dst_ip"
    assert _map_field("DestinationPort") == "network.dst_port"


def test_map_unknown_field_lowercased():
    assert _map_field("SomeCustomField") == "somecustomfield"


# ── Value modifiers ──────────────────────────────────────────────────────────


def test_value_modifiers():
    assert _sigma_value_to_es("Image", "powershell", ["contains"]) == "process.path:*powershell*"
    assert _sigma_value_to_es("Image", "C:\\x", ["startswith"]).startswith("process.path:C\\:")
    assert _sigma_value_to_es("Image", "evil.exe", ["endswith"]) == "process.path:*evil.exe"
    assert _sigma_value_to_es("Image", "ev.l", ["re"]) == "process.path:/ev.l/"


def test_wildcard_modifiers_escape_lucene_specials():
    # Spaces, parens and colons inside a |contains value must be escaped —
    # unescaped they split the term or break query_string parsing (ES 400s).
    out = _sigma_value_to_es("CommandLine", " -enc (a):", ["contains"])
    assert out == "process.command_line:*\\ \\-enc\\ \\(a\\)\\:*"


def test_exact_value_escapes_lucene_specials():
    # ':' and '\' are Lucene specials and must be backslash-escaped.
    out = _sigma_value_to_es("CommandLine", "a:b", [])
    assert out == "process.command_line:a\\:b"


# ── Selections ───────────────────────────────────────────────────────────────


def test_selection_dict_joins_with_and():
    out = _sigma_selection_to_es({"Image": "x", "CommandLine": "y"})
    assert " AND " in out
    assert "process.path:x" in out
    assert "process.command_line:y" in out


def test_selection_list_value_is_ored():
    out = _sigma_selection_to_es({"Image": ["a", "b"]})
    assert out == "(process.path:a OR process.path:b)"


def test_field_modifier_syntax_in_selection():
    out = _sigma_selection_to_es({"CommandLine|contains": "mimikatz"})
    assert out == "process.command_line:*mimikatz*"


# ── Full condition expressions ───────────────────────────────────────────────


def test_simple_selection_condition():
    sigma = {"detection": {"selection": {"Image": "evil.exe"}, "condition": "selection"}}
    assert _sigma_to_es_query(sigma) == "process.path:evil.exe"


def test_and_not_condition():
    sigma = {
        "detection": {
            "selection": {"Image": "evil.exe"},
            "filter": {"User": "system"},
            "condition": "selection and not filter",
        }
    }
    out = _sigma_to_es_query(sigma)
    assert "AND NOT" in out
    assert "process.path:evil.exe" in out
    assert "user.name:system" in out


def test_or_condition():
    sigma = {
        "detection": {
            "sel1": {"Image": "a.exe"},
            "sel2": {"Image": "b.exe"},
            "condition": "sel1 or sel2",
        }
    }
    out = _sigma_to_es_query(sigma)
    assert " OR " in out
    assert "a.exe" in out and "b.exe" in out


def test_one_of_pattern():
    sigma = {
        "detection": {
            "selection_a": {"Image": "a.exe"},
            "selection_b": {"Image": "b.exe"},
            "condition": "1 of selection*",
        }
    }
    out = _sigma_to_es_query(sigma)
    assert " OR " in out


def test_one_of_them_ores_all_selections():
    # `1 of them` must resolve to every named selection — not the match-all `*`.
    sigma = {
        "detection": {
            "sel_a": {"Image": "a.exe"},
            "sel_b": {"Image": "b.exe"},
            "condition": "1 of them",
        }
    }
    out = _sigma_to_es_query(sigma)
    assert out == "(process.path:a.exe) OR (process.path:b.exe)"


def test_all_of_pattern_ands_selections():
    sigma = {
        "detection": {
            "selection_a": {"Image": "a.exe"},
            "selection_b": {"Image": "b.exe"},
            "other": {"Image": "c.exe"},
            "condition": "all of selection_*",
        }
    }
    out = _sigma_to_es_query(sigma)
    assert out == "(process.path:a.exe) AND (process.path:b.exe)"


def test_parenthesised_condition_precedence():
    # Parens bind tighter than or: a AND (b OR c), not (a AND b) OR c.
    sigma = {
        "detection": {
            "a": {"Image": "a.exe"},
            "b": {"Image": "b.exe"},
            "c": {"Image": "c.exe"},
            "condition": "a and (b or c)",
        }
    }
    out = _sigma_to_es_query(sigma)
    assert out == (
        "(process.path:a.exe) AND "
        "((process.path:b.exe) OR (process.path:c.exe))"
    )


def test_not_one_of_pattern_negates_resolved_subquery():
    # `not 1 of filter_*` must negate the resolved filter selections — the
    # quantifier expression itself must never leak into the query literally.
    sigma = {
        "detection": {
            "selection": {"Image": "evil.exe"},
            "filter_main_1": {"User": "system"},
            "filter_main_2": {"User": "admin"},
            "filter_optional_1": {"Computer": "dc01"},
            "condition": "selection and not 1 of filter_main_* and not 1 of filter_optional_*",
        }
    }
    out = _sigma_to_es_query(sigma)
    assert " 1 of " not in out
    assert "AND NOT ((user.name:system) OR (user.name:admin))" in out
    assert "AND NOT ((host.hostname:dc01))" in out
    assert "process.path:evil.exe" in out


def test_null_value_means_field_absent():
    sigma = {
        "detection": {"selection": {"Image": None}, "condition": "selection"}
    }
    assert _sigma_to_es_query(sigma) == "NOT _exists_:process.path"


def test_contains_all_list_is_anded():
    # `|contains|all` requires every value — OR would fire on any one of them.
    sigma = {
        "detection": {
            "selection": {"CommandLine|contains|all": ["new-object", "net.webclient"]},
            "condition": "selection",
        }
    }
    out = _sigma_to_es_query(sigma)
    assert out == (
        "(process.command_line:*new\\-object* AND process.command_line:*net.webclient*)"
    )


def test_no_detection_falls_back_to_title():
    assert _sigma_to_es_query({"title": "MyRule"}) == 'title:"MyRule"'


def test_no_detection_title_with_spaces_and_colons_is_quoted():
    assert _sigma_to_es_query({"title": "My Rule: X"}) == 'title:"My Rule: X"'
