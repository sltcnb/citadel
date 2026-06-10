"""Tests for Sigil convert + coverage. Standalone: `python3 test_sigil_tools.py`."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sigil_convert as conv  # noqa: E402
import sigil_coverage as cov  # noqa: E402


def test_field_modifiers():
    assert conv._field_match("CommandLine|contains", "evil") == "CommandLine:*evil*"
    assert conv._field_match("Image|endswith", "\\find.exe").endswith("find.exe")
    assert conv._field_match("Image|startswith", "C").startswith("Image:")


def test_list_value_is_or():
    q = conv._field_match("OriginalFileName", ["FIND.EXE", "FINDSTR.EXE"])
    assert " OR " in q and q.startswith("(")


def test_all_of_selection_is_and():
    det = (
        "condition: all of selection_*\n"
        "selection_cli:\n  CommandLine|contains: ' 385201'\n"
        "selection_img:\n- Image|endswith:\n  - \\find.exe\n"
    )
    q = conv.sigma_detection_to_query(det)
    assert "AND" in q and "385201" in q


def test_one_of_is_or():
    det = "condition: 1 of selection_*\nselection_a:\n  A: 1\nselection_b:\n  B: 2\n"
    q = conv.sigma_detection_to_query(det)
    assert " OR " in q


def test_convert_whole_corpus_no_failures():
    assert conv.convert_all() == 0


def test_coverage_matrix_builds():
    data = cov.build()
    assert data["totals"]["rules"] > 100
    assert data["totals"]["tactics_covered"] >= 10
    md = cov.render_md(data)
    assert md.startswith("# Sigil") and "| Tactic |" in md


if __name__ == "__main__":
    n = 0
    for name in sorted(dir()):
        if name.startswith("test_"):
            globals()[name]()
            n += 1
            print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
