"""Elasticsearch bulk indexing helper."""

from __future__ import annotations

import gzip
import json
import logging
from typing import Any

import requests
import requests.adapters

logger = logging.getLogger(__name__)

# compresslevel=1 gives ~70-80% payload reduction with minimal CPU overhead.
_COMPRESS_LEVEL = 1
# Resilient retry: critically, allowed_methods MUST include POST — urllib3's
# default set excludes it, so without this the _bulk POST got ZERO retries and a
# transient DNS blip / ES restart / read-timeout failed the whole ingest job.
# Exponential backoff (1,2,4,8,16s) rides out an ES pod restart.
_RETRY = requests.adapters.Retry(
    total=5,
    connect=5,
    read=3,
    backoff_factor=1.0,
    status_forcelist=[429, 502, 503, 504],
    allowed_methods=frozenset(["POST", "GET"]),
    raise_on_status=False,
)
# (connect timeout, read timeout). Big batches need a generous read budget.
_TIMEOUT = (10, 120)
# Cap a single _bulk request so one giant batch can't time out or pressure ES.
_MAX_DOCS_PER_BULK = 2000
_MAX_BYTES_PER_BULK = 15 * 1024 * 1024  # ~15 MB uncompressed ndjson


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
        """Bulk index events, split into bounded sub-batches.

        One huge _bulk request (a 1 GB file's worth, or a single oversized doc)
        timed out and pressured ES into the DNS/read-timeout failures seen in
        prod. Chunk by doc count AND byte size so each request stays small and
        retryable.
        """
        if not events:
            return

        batch: list[str] = []
        batch_docs = 0
        batch_bytes = 0
        for event in events:
            event = _sanitize(event)
            artifact_type = event.get("artifact_type", "generic")
            index = _index_name(case_id, artifact_type)
            doc_id = event.get("fo_id", "")
            action = json.dumps({"index": {"_index": index, "_id": doc_id}})
            doc = json.dumps(event)
            batch.append(action)
            batch.append(doc)
            batch_docs += 1
            batch_bytes += len(action) + len(doc) + 2
            if batch_docs >= _MAX_DOCS_PER_BULK or batch_bytes >= _MAX_BYTES_PER_BULK:
                self._flush(batch, batch_docs)
                batch, batch_docs, batch_bytes = [], 0, 0
        if batch:
            self._flush(batch, batch_docs)

    def _flush(self, lines: list[str], n_docs: int) -> None:
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
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            result = resp.json()
            if result.get("errors"):
                error_items = [
                    item for item in result.get("items", []) if item.get("index", {}).get("error")
                ]
                logger.error(
                    "Bulk indexing had %d errors (of %d total)", len(error_items), n_docs
                )
                for item in error_items[:5]:
                    logger.error("Bulk error detail: %s", item)
            else:
                logger.debug("Bulk indexed %d events", n_docs)
        except requests.HTTPError as exc:
            logger.error(
                "ES bulk HTTP error %d: %s", exc.response.status_code, exc.response.text[:500]
            )
            raise
        except Exception as exc:
            logger.error("ES bulk failed: %s", exc)
            raise
