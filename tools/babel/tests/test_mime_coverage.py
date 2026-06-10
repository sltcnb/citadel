"""Enforce MIME-type coverage across every Babel parser.

Every parser must either declare ``SUPPORTED_MIME_TYPES`` or be explicitly
listed as intentionally exempt (filename/extension/behavioural routing). A new
parser that does neither fails this test, which is the contract Babel owes
Sluice: the router needs a MIME declaration to dispatch by content type.
"""

from __future__ import annotations

from .mime_coverage import build_report, discover_parsers


def test_no_mime_coverage_gaps():
    report = build_report()
    assert report["gaps"] == [], (
        f"parsers missing SUPPORTED_MIME_TYPES (and not exempt): {report['gaps']}. "
        f"Declare accurate MIME types or add to INTENTIONALLY_NO_MIME with a reason."
    )


def test_every_parser_is_routable():
    # A parser with no MIME, no extension, no filename, and no can_handle
    # override could never be selected by the loader — that is always a bug.
    report = build_report()
    assert report["unroutable"] == [], (
        f"unroutable parsers (loader can never select them): {report['unroutable']}"
    )


def test_discovers_full_parser_suite():
    # Guards against the discovery glob silently breaking. Babel ships 40+ parsers.
    parsers = discover_parsers()
    assert len(parsers) >= 40, f"expected the full Babel suite, found {len(parsers)}"


def test_declared_mime_types_are_wellformed():
    for p in discover_parsers():
        for mt in p.mime_types:
            assert "/" in mt and mt == mt.strip().lower(), (
                f"{p.name}: malformed MIME type {mt!r} (expected lowercase 'type/subtype')"
            )
