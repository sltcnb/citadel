"""Regression tests: scoped upload tokens (upl claim).

Collector packages left on forensic targets need an upload credential, but
embedding the analyst's full session JWT meant a script read = full session
takeover. Upload tokens are minted server-side, accepted ONLY on
evidence-upload endpoints (require_upload_access), and rejected by
get_current_user everywhere else.

Uses the fakeredis `fake_redis` fixture from api/conftest.py.
"""

import asyncio
import sys
import time
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auth import service as svc  # noqa: E402
from auth.dependencies import get_current_user, require_upload_access  # noqa: E402
from services.upload_tokens import create_upload_token  # noqa: E402


class _Req:
    def __init__(self):
        self.query_params = {}


def _seed_case(fake, case_id="case1", company="Acme"):
    fake.hset(f"case:{case_id}", mapping={"case_id": case_id, "name": "Test", "company": company})
    fake.sadd("cases:all", case_id)


def test_upload_token_rejected_as_access_token(fake_redis):
    svc.create_user("field", "pw12345!", role="analyst")
    upl = create_upload_token("field")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(get_current_user(_Req(), upl))
    assert exc.value.status_code == 401


def test_upload_token_accepted_on_upload_path(fake_redis):
    svc.create_user("field", "pw12345!", role="analyst", companies=["Acme"])
    _seed_case(fake_redis, "case1", "Acme")
    case = require_upload_access("case1", _Req(), create_upload_token("field"))
    assert case["case_id"] == "case1"


def test_upload_token_company_scoped(fake_redis):
    svc.create_user("field", "pw12345!", role="analyst", companies=["Acme"])
    _seed_case(fake_redis, "other", "OtherCorp")
    with pytest.raises(HTTPException) as exc:
        require_upload_access("other", _Req(), create_upload_token("field"))
    assert exc.value.status_code == 403


def test_upload_path_rejects_challenge_tokens(fake_redis):
    svc.create_user("field", "pw12345!", role="analyst", companies=["Acme"])
    _seed_case(fake_redis, "case1", "Acme")
    with pytest.raises(HTTPException) as exc:
        require_upload_access("case1", _Req(), svc.create_mfa_challenge("field"))
    assert exc.value.status_code == 401


def test_upload_path_still_accepts_access_tokens(fake_redis):
    svc.create_user("analyst1", "pw12345!", role="analyst", companies=["Acme"])
    _seed_case(fake_redis, "case1", "Acme")
    case = require_upload_access("case1", _Req(), svc.create_token("analyst1", "analyst"))
    assert case["case_id"] == "case1"


def test_upload_token_ttl_is_hours_not_session_length(fake_redis):
    payload = svc.decode_token(create_upload_token("field"))
    # ~24h by default — bounded, and far from indefinite.
    assert 23 * 3600 < payload["exp"] - time.time() <= 24 * 3600
