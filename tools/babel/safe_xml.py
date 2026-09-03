"""Hardened XML parsing for Babel plugins.

Plugins parse XML that came off a seized device or out of an uploaded triage
archive: `packages.xml` from an Android dump, WiFi configs, WER reports. That
input is attacker-influenced — whoever had the device before collection chose
what the parser sees.

`xml.etree.ElementTree` parses that input with entity expansion enabled:

  * External entities are already refused — ET installs no resolver, so
    `<!ENTITY x SYSTEM "file:///etc/passwd">` raises "undefined entity" rather
    than reading the file. That much is safe on stock CPython.
  * Internal entities expand freely, and that is the billion-laughs /
    quadratic-blowup denial of service: a few hundred bytes of XML that
    expands to gigabytes inside the processor and takes the worker down.

The parser here refuses entity declarations outright, so neither class depends
on how the underlying expat build happens to be configured. It drives expat
directly (rather than ET.XMLParser, whose `.parser` handle for installing
these handlers was removed in Python 3.13) and is stdlib-only, keeping the
"no third-party dependencies" property of the plugin packs — a defusedxml
dependency would break vendoring.

Use these instead of ET.parse / ET.fromstring anywhere the XML is evidence::

    from babel.safe_xml import parse_file, parse_string

    tree = parse_file(path)      # ET.ElementTree
    root = parse_string(text)    # ET.Element

Both raise ET.ParseError on malformed input and on a rejected entity, so
existing `except ET.ParseError` handlers keep working unchanged.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import xml.parsers.expat
from pathlib import Path

__all__ = ["parse_file", "parse_string"]


class EntityDeclarationRejected(ET.ParseError):
    """An evidence file declared an XML entity. Subclass of ET.ParseError so
    callers that already handle parse failures need no change."""


def _parse(data: bytes) -> ET.Element:
    builder = ET.TreeBuilder()
    # namespace_separator="}" makes expat report namespaced names as
    # "uri}local"; ET's own parser does the same and prepends "{" to get the
    # canonical "{uri}local" form, which is what plugins match on.
    parser = xml.parsers.expat.ParserCreate(namespace_separator="}")

    def _fix(name: str) -> str:
        return "{" + name if "}" in name else name

    def _start(name, attrs):
        builder.start(_fix(name), {_fix(k): v for k, v in attrs.items()})

    def _end(name):
        builder.end(_fix(name))

    def _entity_decl(*_args, **_kwargs):
        raise EntityDeclarationRejected(
            "XML entity declaration rejected: entity expansion in evidence "
            "files is a denial-of-service vector (billion laughs)"
        )

    def _external_entity(*_args, **_kwargs) -> bool:
        # Returning false makes expat raise, rather than silently skipping.
        return False

    parser.StartElementHandler = _start
    parser.EndElementHandler = _end
    parser.CharacterDataHandler = builder.data
    parser.EntityDeclHandler = _entity_decl
    parser.ExternalEntityRefHandler = _external_entity

    try:
        parser.Parse(data, True)
    except xml.parsers.expat.ExpatError as exc:
        # Normalise to the exception type plugins already catch.
        raise ET.ParseError(str(exc)) from exc
    return builder.close()


def parse_string(text: str | bytes) -> ET.Element:
    """ET.fromstring() with entity processing disabled."""
    return _parse(text.encode("utf-8") if isinstance(text, str) else text)


def parse_file(path: str | Path) -> ET.ElementTree:
    """ET.parse() with entity processing disabled."""
    with open(path, "rb") as fh:
        return ET.ElementTree(_parse(fh.read()))
