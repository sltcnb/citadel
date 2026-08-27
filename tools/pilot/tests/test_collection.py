"""The return path: an analysis gap becomes a runnable collection instruction.

The pipeline only ran one way. Talon collects, Babel parses, Pilot analyses —
and when Pilot found the evidence it needed was never gathered, that knowledge
died in a report. "Not enough evidence to reach a decision" is the most common
verdict precisely because nothing carried the finding back to the stage that
could fix it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pilot.collection import (  # noqa: E402
    collection_catalog,
    infer_os,
    plan_collection,
    supported_artifact_types,
)


def test_gap_becomes_a_runnable_command():
    r = plan_collection(["browser", "process"], host="L20336", os_family="macos")
    assert r.is_actionable
    cmd = r.command()
    assert cmd.startswith("talon --collect")
    assert "browser" in cmd and "triage" in cmd


def test_macos_browser_request_names_the_real_macos_paths():
    """A request that says "browser history" without saying where is not
    actionable — the path differs on every OS."""
    r = plan_collection(["browser"], host="L20336", os_family="macos")
    joined = " ".join(r.fetch_paths)
    assert "Library/Safari/History.db" in joined
    assert "QuarantineEventsV2" in joined
    assert "AppData" not in joined  # no Windows paths on a Mac request


def test_windows_request_does_not_leak_macos_paths():
    r = plan_collection(["browser"], host="WS01", os_family="windows")
    joined = " ".join(r.fetch_paths)
    assert "AppData" in joined
    assert "Library/Safari" not in joined


def test_unknown_os_covers_all_three_rather_than_guessing():
    """An over-broad re-collection is recoverable; a wrong one wastes the only
    chance to touch the host."""
    r = plan_collection(["browser"], host="H", os_family="unknown")
    joined = " ".join(r.fetch_paths)
    assert "Library/Safari" in joined and "AppData" in joined


def test_os_is_inferred_from_artifact_types_already_present():
    assert infer_os(["plist", "macos_uls", "syslog"]) == "macos"
    assert infer_os(["evtx", "registry", "prefetch"]) == "windows"
    assert infer_os(["auditd", "iptables"]) == "linux"


def test_os_inference_admits_when_it_cannot_tell():
    """Better unknown — which fans out — than a confident wrong OS."""
    assert infer_os(["syslog"]) == "unknown"
    assert infer_os([]) == "unknown"


def test_request_explains_why_each_type_is_wanted():
    """An operator asked to re-touch a production host needs the reason."""
    r = plan_collection(["browser", "persistence"], host="H", os_family="macos")
    joined = " ".join(r.rationale)
    assert "browser:" in joined
    assert "survives a reboot" in joined


def test_type_unavailable_on_this_os_is_reported_not_silently_dropped():
    """Requesting EVTX from a Mac is not a gap the operator can close."""
    r = plan_collection(["evtx"], host="L20336", os_family="macos")
    assert not r.is_actionable
    assert any("evtx" in u for u in r.unmapped)


def test_unmappable_type_is_surfaced():
    r = plan_collection(["some_future_type"], host="H", os_family="linux")
    assert "some_future_type" in r.unmapped


def test_explicit_paths_are_carried_through():
    """The agent may know the exact file when the category is too coarse."""
    r = plan_collection(
        ["file"], host="H", os_family="linux", extra_paths=["/tmp/payload.bin"]
    )
    assert "/tmp/payload.bin" in r.fetch_paths
    assert "/tmp/payload.bin" in r.command()


def test_categories_and_paths_are_deduplicated():
    r = plan_collection(["browser", "browser", "persistence"], host="H", os_family="macos")
    assert len(r.categories) == len(set(r.categories))
    assert len(r.fetch_paths) == len(set(r.fetch_paths))


def test_request_serialises_for_the_report():
    d = plan_collection(["browser"], host="L20336", os_family="macos").as_dict()
    assert d["host"] == "L20336"
    assert d["actionable"] is True
    assert d["command"].startswith("talon ")
    assert isinstance(d["rationale"], list)


def test_catalog_is_exposed_for_the_admin_surface():
    cat = collection_catalog()
    assert cat and all("artifact_type" in c and "why" in c and "by_os" in c for c in cat)
    assert {c["artifact_type"] for c in cat} == set(supported_artifact_types())


def test_every_mapped_type_produces_something_for_at_least_one_os():
    for atype in supported_artifact_types():
        assert plan_collection([atype], host="H", os_family="unknown").is_actionable, atype
