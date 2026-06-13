"""Unit tests for the multi-tenant access-control primitives in auth.dependencies.

`get_company_filter` (pure) and `require_case_access` (loads a case via
services.cases.get_case, which the `fake_redis` fixture backs). These guard the
IDOR surface the routers depend on, so the matrix here is the safety net for the
`Depends(require_case_access)` wiring across case-scoped endpoints.
"""

import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auth.dependencies import get_company_filter, require_case_access  # noqa: E402


# ── get_company_filter ───────────────────────────────────────────────────────


def test_admin_is_unrestricted():
    assert get_company_filter({"role": "admin", "companies": ["Acme"]}) is None


def test_empty_companies_is_unrestricted():
    assert get_company_filter({"role": "analyst", "companies": []}) is None


def test_restricted_list_returned():
    assert get_company_filter({"role": "analyst", "companies": ["Acme"]}) == ["Acme"]


def test_companies_json_string_parsed():
    # Redis hashes store companies as a JSON string.
    assert get_company_filter({"role": "analyst", "companies": '["Acme", "Beta"]'}) == [
        "Acme",
        "Beta",
    ]


def test_companies_bad_json_treated_as_unrestricted():
    assert get_company_filter({"role": "analyst", "companies": "not-json"}) is None


# ── require_case_access ──────────────────────────────────────────────────────


def _make_case(fake_redis, case_id, company):
    fake_redis.hset(f"case:{case_id}", mapping={"case_id": case_id, "company": company})


def test_missing_case_404(fake_redis):
    with pytest.raises(HTTPException) as ei:
        require_case_access("nope", {"role": "analyst", "companies": ["Acme"]})
    assert ei.value.status_code == 404


def test_wrong_company_403(fake_redis):
    _make_case(fake_redis, "c1", "Acme")
    with pytest.raises(HTTPException) as ei:
        require_case_access("c1", {"role": "analyst", "companies": ["Beta"]})
    assert ei.value.status_code == 403


def test_matching_company_passes(fake_redis):
    _make_case(fake_redis, "c1", "Acme")
    case = require_case_access("c1", {"role": "analyst", "companies": ["Acme"]})
    assert case["case_id"] == "c1"


def test_admin_bypasses_company(fake_redis):
    _make_case(fake_redis, "c1", "Acme")
    case = require_case_access("c1", {"role": "admin", "companies": []})
    assert case["case_id"] == "c1"


def test_unrestricted_analyst_passes(fake_redis):
    # analyst with no company restriction is unrestricted (get_company_filter → None)
    _make_case(fake_redis, "c1", "Acme")
    case = require_case_access("c1", {"role": "analyst", "companies": []})
    assert case["case_id"] == "c1"
