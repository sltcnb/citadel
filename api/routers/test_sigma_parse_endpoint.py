"""Endpoint-level tests for POST /alert-rules/sigma/parse (the parse preview).

The preview must not just convert the Sigma rule — it must also run the
produced Lucene through services.elasticsearch.validate_lucene_query and hand
the verdict back (``query_valid`` / ``query_error``) so the frontend modal can
warn BEFORE the rule is saved and starts 400-ing every search.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routers import global_alert_rules as gar  # noqa: E402

pytestmark = pytest.mark.skipif(not gar._YAML_AVAILABLE, reason="PyYAML not installed")

_RULE = """\
title: Suspicious PsExec
description: demo rule
logsource:
  product: windows
detection:
  selection:
    Image: psexec.exe
  condition: selection
level: high
"""


@pytest.fixture(autouse=True)
def _sigma_enabled(monkeypatch):
    monkeypatch.setattr(gar, "get_global_sigma_enabled", lambda: True)


def test_parse_includes_lucene_validation_ok():
    out = gar.parse_sigma_rule({"yaml": _RULE})
    assert out["query"] == "process.path:psexec.exe"
    assert out["query_valid"] is True
    assert out["query_error"] is None


def test_parse_surfaces_lucene_validation_error(monkeypatch):
    # Force the validator to fail and check the verdict is surfaced verbatim.
    monkeypatch.setattr(gar, "validate_lucene_query", lambda q: "unbalanced '('")
    out = gar.parse_sigma_rule({"yaml": _RULE})
    assert out["query_valid"] is False
    assert out["query_error"] == "unbalanced '('"
