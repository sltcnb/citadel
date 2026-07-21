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
    urllib.request.install_opener(
        urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(mgr))
    )
    _installed = True
    logger.info("Installed scoped Elasticsearch basic-auth for %s", ES_URL)
