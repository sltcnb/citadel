"""Tests for BitLocker recovery-key redaction in the cases router.

The raw key is a decryption secret; API responses must expose only a boolean.
The disk-image worker reads the raw value from Redis directly (not via the API),
so redacting the response does not break decryption.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routers.cases import _redact_case  # noqa: E402


def test_key_present_redacted_to_boolean():
    out = _redact_case({"name": "c1", "bitlocker_recovery_key": "123456-7890"})
    assert "bitlocker_recovery_key" not in out
    assert out["bitlocker_key_set"] is True
    assert out["name"] == "c1"


def test_no_key_reports_false():
    out = _redact_case({"name": "c1"})
    assert "bitlocker_recovery_key" not in out
    assert out["bitlocker_key_set"] is False


def test_empty_key_reports_false():
    out = _redact_case({"name": "c1", "bitlocker_recovery_key": ""})
    assert out["bitlocker_key_set"] is False


def test_none_passthrough():
    assert _redact_case(None) is None
