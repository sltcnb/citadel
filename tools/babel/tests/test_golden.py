"""Golden-file regression tests for representative Babel parsers.

For each registered :class:`GoldenCase` we:

1. parse a checked-in fixture artifact,
2. assert the (scrubbed) event stream byte-for-byte matches the golden JSON,
3. assert every emitted event validates against the shared ForensicEvent
   contract (``contracts/forensic_event.schema.json``).

Regenerate goldens after an intentional parser change with::

    cd tools && BABEL_REGEN_GOLDEN=1 python -m pytest plugins/tests/test_golden.py
"""

from __future__ import annotations

import os

import pytest

from .golden import harness
from .golden.cases import CASES

_REGEN = os.environ.get("BABEL_REGEN_GOLDEN") == "1"

_CASE_IDS = [c.id for c in CASES]


@pytest.fixture(scope="session")
def schema_validator():
    return harness.load_schema_validator()


@pytest.mark.parametrize("case", CASES, ids=_CASE_IDS)
def test_golden_matches(case):
    events = harness.run_case(case)

    if _REGEN:
        harness.write_golden(case, events)
        pytest.skip(f"regenerated golden for {case.id}")

    assert case.expected_path.exists(), (
        f"missing golden {case.expected_path}; run BABEL_REGEN_GOLDEN=1 pytest to create it"
    )
    expected = harness.load_golden(case)
    assert events == expected, f"parser output diverged from golden for {case.id}"


@pytest.mark.parametrize("case", CASES, ids=_CASE_IDS)
def test_emitted_events_are_contract_valid(case, schema_validator):
    if schema_validator is None:
        pytest.skip("jsonschema not installed")

    events = harness.run_case(case)
    assert events, f"{case.id} emitted no events"
    for i, event in enumerate(events):
        # The contract requires a non-empty ISO-8601 timestamp + message. Parsers
        # may legitimately defer timestamps to the loader (mtime fallback); these
        # golden fixtures deliberately exercise events that already carry one.
        assert event.get("timestamp"), f"{case.id}[{i}] has empty timestamp"
        assert event.get("message"), f"{case.id}[{i}] has empty message"
        schema_validator(event)
