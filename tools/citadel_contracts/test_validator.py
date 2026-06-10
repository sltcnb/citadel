"""Tests for the runtime ForensicEvent validator. Standalone-runnable."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # tools/ for the package
from citadel_contracts import STRUCTURED_ARTIFACTS, validate_forensic_event  # noqa: E402


def test_valid_event_passes():
    # generic_text is not a structured type, so no 'raw' is required
    ok, err = validate_forensic_event(
        {"timestamp": "2026-01-02T03:04:05Z", "message": "hi", "artifact_type": "generic_text"}
    )
    assert ok and err is None, err


def test_missing_fields_rejected():
    assert not validate_forensic_event({"message": "x"})[0]
    assert not validate_forensic_event({"timestamp": "2026-01-02T03:04:05Z"})[0]
    assert not validate_forensic_event("not a dict")[0]


def test_non_z_timestamp_rejected():
    ok, err = validate_forensic_event({"timestamp": "2026-01-02T03:04:05+00:00", "message": "x"})
    assert not ok and "Z" in err


def test_structured_type_requires_raw():
    at = next(iter(STRUCTURED_ARTIFACTS))
    ok, err = validate_forensic_event(
        {"timestamp": "2026-01-02T03:04:05Z", "message": "x", "artifact_type": at}
    )
    assert not ok and "raw" in err
    ok2, _ = validate_forensic_event(
        {
            "timestamp": "2026-01-02T03:04:05Z",
            "message": "x",
            "artifact_type": at,
            "raw": {"k": "v"},
        }
    )
    assert ok2


if __name__ == "__main__":
    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        globals()[name]()
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
