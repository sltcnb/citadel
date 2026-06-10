"""Sluice routing-coverage test. Standalone-runnable + pytest."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from routing_coverage import build_report  # noqa: E402


def test_every_built_row_has_a_handler_and_routes():
    r = build_report()
    assert r["manifests"] > 0
    assert r["missing_handler_module"] == [], r["missing_handler_module"]
    assert r["true_unrouted"] == [], r["true_unrouted"]
    # in a complete environment all signals route; allow env import gaps but
    # require that nothing loaded is left unrouted (asserted above) and that
    # the bulk of signals resolve.
    assert r["signals_routed"] >= r["signals_total"] - 0


if __name__ == "__main__":
    test_every_built_row_has_a_handler_and_routes()
    print("PASS  test_every_built_row_has_a_handler_and_routes")
    print("\n1/1 passed")
