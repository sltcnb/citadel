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
    assert _map_field("Image") == "process.executable"
    assert _map_field("TargetUserName") == "user.name"
    assert _map_field("DestinationIp") == "network.dest_ip"


def test_map_unknown_field_lowercased():
    assert _map_field("SomeCustomField") == "somecustomfield"


# ── Value modifiers ──────────────────────────────────────────────────────────


def test_value_modifiers():
    assert _sigma_value_to_es("Image", "powershell", ["contains"]) == "process.executable:*powershell*"
    assert _sigma_value_to_es("Image", "C:\\x", ["startswith"]).startswith("process.executable:C:")
    assert _sigma_value_to_es("Image", "evil.exe", ["endswith"]) == "process.executable:*evil.exe"
    assert _sigma_value_to_es("Image", "ev.l", ["re"]) == "process.executable:/ev.l/"


def test_exact_value_escapes_lucene_specials():
    # ':' and '\' are Lucene specials and must be backslash-escaped.
    out = _sigma_value_to_es("CommandLine", "a:b", [])
    assert out == "process.command_line:a\\:b"


# ── Selections ───────────────────────────────────────────────────────────────


def test_selection_dict_joins_with_and():
    out = _sigma_selection_to_es({"Image": "x", "CommandLine": "y"})
    assert " AND " in out
    assert "process.executable:x" in out
    assert "process.command_line:y" in out


def test_selection_list_value_is_ored():
    out = _sigma_selection_to_es({"Image": ["a", "b"]})
    assert out == "(process.executable:a OR process.executable:b)"


def test_field_modifier_syntax_in_selection():
    out = _sigma_selection_to_es({"CommandLine|contains": "mimikatz"})
    assert out == "process.command_line:*mimikatz*"


# ── Full condition expressions ───────────────────────────────────────────────


def test_simple_selection_condition():
    sigma = {"detection": {"selection": {"Image": "evil.exe"}, "condition": "selection"}}
    assert _sigma_to_es_query(sigma) == "process.executable:evil.exe"


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
    assert "process.executable:evil.exe" in out
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


def test_no_detection_falls_back_to_title():
    assert _sigma_to_es_query({"title": "MyRule"}) == "title:MyRule"
