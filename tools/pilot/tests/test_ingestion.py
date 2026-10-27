"""Alert text must reach the agent, its anchors and its IOCs byte-for-byte.

A path like C:\\Windows\\testFile.tmp contains "\\t" — one escape decode anywhere
on the way turns it into a TAB and the IOC silently stops matching anything.
"""
import json

import pytest

from pilot.anchors import JOIN_KEYS, extract_anchors
from pilot.iocs import normalize_iocs, path_problem, suggest_repair

PATHS = [
    r"C:\Windows\testIsShareWriteable_ab12.tmp",      # \t
    r"C:\Windows\notes\new_run.ps1",                  # \n twice
    r"C:\Users\ruth\run.bat",                         # \r
    r"C:\ProgramData\x\\double.dll",                  # literal double backslash
    r"\\fileserver01\ADMIN$\temp\drop.exe",           # UNC
]


@pytest.mark.parametrize("path", PATHS)
def test_paths_survive_json_storage_and_anchor_extraction(path):
    alert = f"Machine : srv-x01\n\nThe file {path} was written.\n"
    stored = json.loads(json.dumps({"circumstance": alert}))["circumstance"]
    assert stored == alert
    got = [a.value for a in extract_anchors(stored) if a.kind == "path"]
    assert got == [path]
    assert path_problem(path) is None


def test_join_keys_are_extracted():
    text = (
        "Source port : 64001\nLogon ID: 0x3E7A1\nProcess ID: 4412\n"
        "Session ID: 7\nCorrelation ID: {1b4e28ba-2fa1-11d2-883f-0016d3cca427}\n"
    )
    kinds = {(a.kind, a.value) for a in extract_anchors(text)}
    assert ("port", "64001") in kinds
    assert ("logon_id", "0x3E7A1") in kinds
    assert ("pid", "4412") in kinds
    assert ("session_id", "7") in kinds
    assert ("correlation_id", "1b4e28ba-2fa1-11d2-883f-0016d3cca427") in kinds
    assert set(JOIN_KEYS) >= {"port", "logon_id"}


def test_corrupted_paths_are_withheld_with_a_suggested_original():
    tab_mangled = "C:Windows\testIsShareWriteable_ab12.tmp"   # real TAB, separators lost
    space_mangled = "C:Windows estIsShareWriteable_ab12.tmp"
    clean, warnings = normalize_iocs([tab_mangled, space_mangled, PATHS[0]])
    assert clean == [PATHS[0]]
    assert len(warnings) == 2
    assert warnings[0]["possible_original"] == r"C:\Windows\testIsShareWriteable_ab12.tmp"
    assert "separator" in warnings[1]["problem"]
    assert suggest_repair("C:Windows") == "C:\\Windows"


def test_iocs_are_refanged_and_deduplicated():
    clean, warnings = normalize_iocs(["evil[.]com", "EVIL.com", "hxxp://x[.]org/a", " 10.0.0.1 ", ""])
    assert clean == ["evil.com", "http://x.org/a", "10.0.0.1"]
    assert warnings == []
