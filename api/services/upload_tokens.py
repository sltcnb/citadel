"""Scoped upload tokens — the credential baked into collector packages.

Collector scripts and harvest bundles are left on (potentially hostile)
forensic targets. They need an API credential to upload evidence back, but
embedding the analyst's full 8h session JWT means anyone reading the script
(or scraping proxy access logs, since it also rode in URL query params) gets
full API access as that analyst. Upload tokens are the bounded alternative:
signed with the same secret, but carrying an ``upl`` claim that
``get_current_user`` rejects everywhere EXCEPT the case-upload endpoints
(``require_upload_access`` in auth.dependencies).
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

from jose import jwt

from config import settings

_DEFAULT_TTL_HOURS = 24


def _ttl() -> timedelta:
    try:
        hours = int(os.getenv("UPLOAD_TOKEN_TTL_HOURS", str(_DEFAULT_TTL_HOURS)))
    except ValueError:
        hours = _DEFAULT_TTL_HOURS
    return timedelta(hours=max(1, min(hours, 24 * 30)))


def create_upload_token(username: str) -> str:
    """Mint a scoped upload token for ``username`` (default TTL 24h,
    env-tunable via UPLOAD_TOKEN_TTL_HOURS). Usable only on evidence-upload
    endpoints — never as a general API access token."""
    payload = {
        "sub": username,
        "upl": True,
        "exp": datetime.now(UTC) + _ttl(),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
