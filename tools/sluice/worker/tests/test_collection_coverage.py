"""Gate the collection→parsing bijection.

``test_routing_coverage.py`` gates the direction "every parser is reachable".
This gates the direction that loses evidence: "every artifact Talon collects
reaches the parser that understands it".

The failure mode is silent, which is why it needs a gate at all. An artifact
with no parser does not error — the ``strings`` catch-all claims it, emits
printable strings, and the run reports success. ``mft/C_$MFT`` lived in exactly
that state: collected on every Windows host, routed to strings because the MFT
parser only knew ``C_MFT`` without the ``$``, filesystem timeline silently gone.

Runnable standalone (python3 tools/sluice/worker/tests/test_collection_coverage.py)
to match the dependency-light convention in scripts/run_tests.sh.
"""

from __future__ import annotations

import sys
from pathlib import Path

_WORKER_ROOT = Path(__file__).resolve().parents[1]
if str(_WORKER_ROOT) not in sys.path:
    sys.path.insert(0, str(_WORKER_ROOT))

import collection_coverage  # noqa: E402
import collection_inventory  # noqa: E402


def test_no_routing_drift():
    """Every declared (artifact → parser) pair still holds against the real router."""
    r = collection_coverage.build_report()
    assert not r["misrouted"], "artifacts claimed by the wrong parser:\n" + "\n".join(
        r["misrouted"]
    )
    assert not r["undeclared_gap"], (
        "a declared parser no longer claims what Talon writes — evidence is "
        "silently falling through to a generic fallback:\n" + "\n".join(r["undeclared_gap"])
    )
    assert not r["stale_gap"], (
        "these artifacts now have a real parser; close the ledger entry in "
        "collection_inventory.py:\n" + "\n".join(r["stale_gap"])
    )
    assert not r["unknown_parser"], "ledger names a parser Babel does not ship:\n" + "\n".join(
        r["unknown_parser"]
    )
    assert not r["silent_empty"], (
        "these parsers claim an artifact and then emit nothing — worse than not "
        "claiming, since the run reports success and the artifact never even "
        "reaches the strings floor:\n" + "\n".join(r["silent_empty"])
    )


def test_every_gap_states_a_reason():
    """A ``parser=None`` row is an IOU, so it must say what is missing and why."""
    undocumented = [a.path for a in collection_inventory.open_gaps() if not a.gap.strip()]
    assert not undocumented, (
        "open gaps with no explanation — a gap without a reason is "
        f"indistinguishable from an oversight: {undocumented}"
    )


def test_empty_ok_rows_state_a_reason():
    """Exempting a row from the zero-event check must be justified in writing.

    Otherwise ``empty_ok`` becomes the easy way to silence a genuinely broken
    parser, which is the exact failure the check exists to catch.
    """
    # A whitespace-only value is truthy, so it would skip the check while saying
    # nothing. Require a real sentence.
    unjustified = [
        a.path
        for a in collection_inventory.ARTIFACTS
        if a.empty_ok and len(a.empty_ok.strip()) < 20
    ]
    assert not unjustified, f"empty_ok set without a substantive reason: {unjustified}"


def test_mft_drive_prefixed_names_route():
    """Regression: the arcnames Talon really writes for a collected $MFT.

    Guarded explicitly because this was the bug that motivated the whole checker,
    and because a static filename list is exactly the kind of thing a later edit
    quietly trims.
    """
    from plugin_loader import PluginLoader

    loader = PluginLoader(
        plugins_dir=collection_coverage.PLUGINS_DIR,
        ingester_dir=collection_coverage.INGESTER_DIR,
    )
    loader.load()

    import tempfile

    sample = b"FILE0\x00\x03\x00" + b"\x00" * 1017
    with tempfile.TemporaryDirectory() as td:
        for name in ("$MFT", "C_$MFT", "D_$MFT", "C_MFT", "D_MFT.BAK"):
            path = Path(td) / name
            path.write_bytes(sample)
            hit = loader.get_plugin(path, "application/octet-stream")
            got = getattr(hit, "PLUGIN_NAME", None)
            assert got == "mft", f"{name} routed to {got!r}, not the MFT parser"

        # And it must not over-claim: a report *about* the MFT is not an MFT.
        for name in ("MFTECmd_output.csv", "mft_notes.txt"):
            path = Path(td) / name
            path.write_bytes(b"x,y,z\n1,2,3\n")
            hit = loader.get_plugin(path, "text/plain")
            assert getattr(hit, "PLUGIN_NAME", None) != "mft", f"{name} wrongly claimed by mft"


def test_inventory_covers_every_talon_category():
    """Every collection category Talon advertises has at least one ledger row.

    Sourced from Talon's own ``ARTIFACT_LABELS`` so adding a collector without a
    parser story fails here rather than shipping as a silent gap. Categories that
    are collection *modes* rather than artifact producers are exempt.
    """
    collect_py = (
        Path(collection_coverage.REPO) / "tools" / "talon" / "collect.py"
    ).read_text(encoding="utf-8")
    start = collect_py.index("ARTIFACT_LABELS = {")
    end = collect_py.index("\n}", start)
    import re

    labels = set(re.findall(r'^\s*"([a-z_0-9]+)":', collect_py[start:end], re.MULTILINE))

    # Not artifact producers: these select *how* collection runs, and their
    # output is filed under the categories above.
    MODES = {"external_disk", "file_search"}

    covered = set(collection_inventory.by_category())
    missing = sorted(labels - covered - MODES)
    assert not missing, (
        "Talon advertises these collection categories with no row in "
        f"collection_inventory.py — each is a potential silent gap: {missing}"
    )


if __name__ == "__main__":
    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        globals()[name]()
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
