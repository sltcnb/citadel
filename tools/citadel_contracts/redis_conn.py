"""Redis connection URL helpers shared across the API and worker images.

Historically every service built its Redis client from ``REDIS_URL`` alone and
ignored the separate ``REDIS_PASSWORD`` env var. When the Redis deployment is
run with ``--requirepass`` the clients then connect without an AUTH command and
every command fails with ``NOAUTH Authentication required`` — surfacing to users
as "Redis unreachable" on the login page.

``redis_url_with_auth`` folds ``REDIS_PASSWORD`` into the URL so a plain
``redis.from_url`` picks the credential up. It is a no-op when no password is
configured or when the URL already carries its own credentials, so it is safe to
call unconditionally at every connection site.

Pure stdlib — no third-party dependencies, per this package's contract.
"""

import os
from urllib.parse import quote, urlsplit, urlunsplit

__all__ = ["redis_url_with_auth"]


def redis_url_with_auth(url: str, password: str | None = None) -> str:
    """Return ``url`` with ``password`` injected as the connection credential.

    - ``password`` defaults to the ``REDIS_PASSWORD`` env var when not given.
    - Returns ``url`` unchanged if no password is available, or if the URL
      already embeds userinfo (``redis://user:pass@host``) — an explicit URL
      credential always wins.
    """
    if password is None:
        password = os.getenv("REDIS_PASSWORD", "")
    if not password:
        return url

    parts = urlsplit(url)
    # Respect an existing credential embedded in the URL.
    if parts.username or parts.password:
        return url

    host = parts.hostname or ""
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    # No username — Redis AUTH with password only uses an empty user segment.
    netloc = f":{quote(password, safe='')}@{host}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
