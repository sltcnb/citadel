"""Shared Elasticsearch authentication for the sluice worker.

ES runs with ``xpack.security.enabled=true``, so every ``_bulk`` / ``_search`` /
``_doc`` request must carry HTTP Basic auth for the built-in ``elastic`` user.
Credentials come from the ELASTICSEARCH_USERNAME / ELASTICSEARCH_PASSWORD env
(injected from the ``elasticsearch-secret``).

Rather than thread auth through the ~25 urllib call sites across the task
modules, ``install_es_auth()`` installs a process-wide opener whose Basic-auth
handler is SCOPED to the ES host — so artifact downloads from MinIO/S3 and any
other urllib traffic never receive the ES credentials. ``ES_AUTH`` is exposed
for the one ``requests.Session`` based client (``es_bulk``), which does not use
the urllib opener.
"""

from __future__ import annotations

import logging
import os
import urllib.request

logger = logging.getLogger(__name__)

ES_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch-service:9200")
_USER = os.getenv("ELASTICSEARCH_USERNAME", "")
_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "")

# (user, password) for requests.Session.auth, or None when no creds are set.
ES_AUTH = (_USER, _PASSWORD) if (_USER and _PASSWORD) else None

_installed = False


def install_es_auth() -> None:
    """Install a global urllib opener that adds Basic auth for ES requests only.
    Idempotent; a no-op when no credentials are configured."""
    global _installed
    if _installed:
        return
    if not ES_AUTH:
        logger.warning("No Elasticsearch credentials configured; requests will be unauthenticated")
        _installed = True
        return
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, ES_URL, _USER, _PASSWORD)

    # Preemptive auth for the ES host. HTTPBasicAuthHandler only retries AFTER
    # a 401 — and ES answers 401 early then closes the connection, so a client
    # still streaming a >1MB bulk body gets a broken pipe instead of the 401 it
    # could answer. That is exactly what dropped 69k hayabusa hits: batches
    # under ~1MB squeaked through, bigger ones never got the retry.
    class _ESPreemptiveAuth(urllib.request.BaseHandler):
        def http_request(self, req):  # noqa: N802 - urllib handler API
            if req.full_url.startswith(ES_URL) and "Authorization" not in req.headers:
                import base64

                cred = base64.b64encode(f"{_USER}:{_PASSWORD}".encode()).decode()
                req.add_header("Authorization", f"Basic {cred}")
            return req

    urllib.request.install_opener(
        urllib.request.build_opener(
            _ESPreemptiveAuth(),
            urllib.request.HTTPBasicAuthHandler(mgr),
        )
    )
    _installed = True
    logger.info("Installed scoped Elasticsearch basic-auth for %s", ES_URL)
