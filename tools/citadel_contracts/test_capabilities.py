"""The telemetry half of the capability advertisement. Standalone-runnable.

A manifest is written by hand, usually by someone adding a tool. These tests
pin that the contract catches the mistakes that would otherwise show up much
later as an empty panel or a failed index-template install.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # tools/ for the package
from citadel_contracts import manifest_from_dict  # noqa: E402


def _m(telemetry):
    return manifest_from_dict({"tool": "t", "telemetry": telemetry})


def test_a_manifest_without_a_telemetry_block_is_valid_and_declares_nothing():
    m = manifest_from_dict({"tool": "scribe"})
    assert m.telemetry is None
    assert m.validate() == []


def test_a_well_formed_block_parses_and_round_trips():
    m = _m({
        "kinds": ["llm"],
        "fields": [{"name": "llm.purpose", "type": "keyword", "label": "Purpose"}],
        "panels": [{"key": "p", "label": "P", "type": "table", "kind": "llm",
                    "group_by": "llm.purpose",
                    "metrics": [{"op": "sum", "field": "llm.total_tokens",
                                 "label": "Tokens", "unit": "tokens"}]}],
    })
    assert m.validate() == []
    assert m.telemetry.kinds == ["llm"]
    assert m.to_dict()["telemetry"]["panels"][0]["group_by"] == "llm.purpose"
    # A round trip must not lose the block.
    again = manifest_from_dict(m.to_dict())
    assert again.telemetry.fields[0].name == "llm.purpose"


def test_an_unknown_field_type_is_rejected():
    errs = _m({"fields": [{"name": "x", "type": "stringy"}], "panels": []}).validate()
    assert any("unknown field type 'stringy'" in e for e in errs)


def test_an_unknown_panel_type_is_rejected():
    errs = _m({"panels": [{"key": "p", "type": "pie"}]}).validate()
    assert any("unknown panel type 'pie'" in e for e in errs)


def test_a_table_panel_without_group_by_is_rejected():
    errs = _m({"panels": [{"key": "p", "type": "table"}]}).validate()
    assert any("needs group_by" in e for e in errs)


def test_an_unknown_metric_op_is_rejected():
    errs = _m({"panels": [{"key": "p", "type": "stat",
                           "metrics": [{"op": "median", "field": "d"}]}]}).validate()
    assert any("unknown metric op 'median'" in e for e in errs)


def test_a_metric_needing_a_field_without_one_is_rejected():
    errs = _m({"panels": [{"key": "p", "type": "stat",
                           "metrics": [{"op": "sum"}]}]}).validate()
    assert any("needs a field" in e for e in errs)


def test_count_is_the_one_op_that_needs_no_field():
    assert _m({"panels": [{"key": "p", "type": "stat",
                           "metrics": [{"op": "count"}]}]}).validate() == []


def test_grouping_by_a_text_field_is_rejected():
    # Elasticsearch would return no buckets rather than an error, which is the
    # worst failure mode: it looks exactly like "nothing happened".
    errs = _m({
        "fields": [{"name": "msg", "type": "text"}],
        "panels": [{"key": "p", "type": "table", "group_by": "msg"}],
    }).validate()
    assert any("cannot group by" in e for e in errs)


def test_a_panel_filtering_a_kind_the_tool_never_declares_is_rejected():
    errs = _m({"kinds": ["llm"],
               "panels": [{"key": "p", "type": "stat", "kind": "task"}]}).validate()
    assert any("does not declare" in e for e in errs)


def test_a_tool_declaring_no_kinds_may_panel_on_another_tools_kind():
    # Anvil adds one field to Sluice's `task` events; that must stay legal.
    assert _m({
        "fields": [{"name": "task.module", "type": "keyword"}],
        "panels": [{"key": "p", "type": "table", "kind": "task",
                    "group_by": "task.module",
                    "metrics": [{"op": "count", "label": "Runs"}]}],
    }).validate() == []


def test_duplicate_panel_keys_are_rejected():
    errs = _m({"panels": [{"key": "p", "type": "stat"}, {"key": "p", "type": "stat"}]}).validate()
    assert any("duplicate panel key" in e for e in errs)


def test_every_shipped_manifest_is_valid():
    """The real advertisements in tools/*/capabilities.yaml must parse clean —
    a typo here silently removes a panel from the Telemetry page."""
    try:
        import yaml
    except ImportError:
        return  # dependency-light gate without PyYAML: nothing to check
    root = Path(__file__).resolve().parents[1]
    checked = 0
    for path in sorted(root.glob("*/capabilities.yaml")):
        doc = yaml.safe_load(path.read_text())
        if not doc:
            continue
        problems = manifest_from_dict(doc).validate()
        assert not problems, f"{path.name}: {problems}"
        checked += 1
    assert checked, "no capability manifests found"


if __name__ == "__main__":
    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        globals()[name]()
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
