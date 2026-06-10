"""Elasticsearch bulk indexing helper."""

from __future__ import annotations

import gzip
import json
import logging
from typing import Any

import requests
import requests.adapters

logger = logging.getLogger(__name__)

# Retry adapter: 3 retries with exponential back-off on connection errors.
# compresslevel=1 gives ~70-80% payload reduction with minimal CPU overhead.
_COMPRESS_LEVEL = 1
_RETRY = requests.adapters.Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 503])


def _index_name(case_id: str, artifact_type: str) -> str:
    return f"fo-case-{case_id}-{artifact_type}"


def _sanitize(obj: Any) -> Any:
    """Recursively replace lone surrogates in string values so json.dumps never fails."""
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8")
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize(v) for v in obj]
    return obj


class ESBulkIndexer:
    def __init__(self, es_url: str) -> None:
        self.es_url = es_url.rstrip("/")
        self._session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=2,
            pool_maxsize=4,
            max_retries=_RETRY,
        )
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    def bulk_index(self, case_id: str, events: list[dict[str, Any]]) -> None:
        """Bulk index a list of events into the appropriate case indices."""
        if not events:
            return

        lines = []
        for event in events:
            event = _sanitize(event)
            artifact_type = event.get("artifact_type", "generic")
            index = _index_name(case_id, artifact_type)
            doc_id = event.get("fo_id", "")
            action = {"index": {"_index": index, "_id": doc_id}}
            lines.append(json.dumps(action))
            lines.append(json.dumps(event))

        body = ("\n".join(lines) + "\n").encode("utf-8")
        compressed = gzip.compress(body, compresslevel=_COMPRESS_LEVEL)

        try:
            resp = self._session.post(
                f"{self.es_url}/_bulk",
                data=compressed,
                headers={
                    "Content-Type": "application/x-ndjson",
                    "Content-Encoding": "gzip",
                    "Accept-Encoding": "gzip",
                },
                timeout=60,
            )
            resp.raise_for_status()
            result = resp.json()
            if result.get("errors"):
                error_items = [
                    item for item in result.get("items", []) if item.get("index", {}).get("error")
                ]
                logger.error(
                    "Bulk indexing had %d errors (of %d total)", len(error_items), len(events)
                )
                for item in error_items[:5]:
                    logger.error("Bulk error detail: %s", item)
            else:
                logger.debug("Bulk indexed %d events", len(events))
        except requests.HTTPError as exc:
            logger.error(
                "ES bulk HTTP error %d: %s", exc.response.status_code, exc.response.text[:500]
            )
            raise
        except Exception as exc:
            logger.error("ES bulk failed: %s", exc)
            raise
