"""Upgrade a case's indices to full-text search (the search_all field).

Indices created before the template gained ``search_all`` keep their old
mapping; Elasticsearch cannot add ``copy_to`` to existing fields, so each one is
rebuilt: copied to a temporary index with the current template's mapping, then
recreated under its own name from that copy.

Safety:
- the temporary index name does not match ``fo-case-<id>-*`` or ``fo-case-*``,
  so neither case search nor cross-case search ever sees a duplicate;
- every copy is verified by document count before the source is deleted;
- the run is resumable: if it dies after deleting an original, the temporary
  copy still exists and the next run restores from it;
- it refuses while the case still has ingest jobs in flight, because documents
  written to an index during its copy would be lost.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import UTC, datetime

from services.elasticsearch import _request, search_all_indices, _SEARCH_ALL_CACHE

logger = logging.getLogger(__name__)

TMP_PREFIX = "citadel-search-upgrade-"
_ACTIVE = ("PENDING", "UPLOADING", "RUNNING", "QUEUED", "PROCESSING")


def _status_key(case_id: str) -> str:
    return f"fo:search_upgrade:{case_id}"


def _tmp_name(index: str) -> str:
    return TMP_PREFIX + index[len("fo-case-"):]


def _count(index: str) -> int:
    _request("POST", f"/{index}/_refresh", None)
    return int(_request("POST", f"/{index}/_count", {"query": {"match_all": {}}})["count"])


def _exists(index: str) -> bool:
    try:
        _request("GET", f"/{index}/_settings", None)
        return True
    except Exception:
        return False


def _create_with_template_mapping(target: str, as_if: str) -> None:
    """Create *target* with the mapping/settings the template gives *as_if*."""
    sim = _request("POST", f"/_index_template/_simulate_index/{as_if}", None)
    tpl = sim.get("template") or {}
    settings = dict((tpl.get("settings") or {}).get("index") or {})
    for k in ("uuid", "creation_date", "provided_name", "version", "routing"):
        settings.pop(k, None)
    _request("PUT", f"/{target}", {"settings": {"index": settings}, "mappings": tpl.get("mappings") or {}})


def _reindex(src: str, dst: str) -> int:
    task = _request("POST", "/_reindex?wait_for_completion=false&slices=auto",
                    {"source": {"index": src, "size": 2000}, "dest": {"index": dst}})["task"]
    while True:
        st = _request("GET", f"/_tasks/{task}", None)
        if st.get("completed"):
            resp = st.get("response") or {}
            if resp.get("failures"):
                raise RuntimeError(f"reindex {src} → {dst}: {json.dumps(resp['failures'][:2])[:300]}")
            return int(resp.get("total") or 0)
        time.sleep(3)


def active_ingest_jobs(case_id: str) -> int:
    from services.jobs import status_counts_for_case

    counts = status_counts_for_case(case_id) or {}
    return sum(int(v) for k, v in counts.items() if str(k).upper() in _ACTIVE)


def _has_search_all(index: str) -> bool:
    m = _request("GET", f"/{index}/_mapping/field/search_all", None) or {}
    return any((v.get("mappings") or {}) for v in m.values())


def upgrade_index(index: str, log) -> dict:
    """Rebuild one index with the current template. Resumes a half-done run.

    Phases are told apart by whether the live index already has search_all:
    an original never does, a rebuild always does. So a temporary copy is only
    ever discarded when the original is still intact beside it."""
    tmp = _tmp_name(index)
    idx_exists, tmp_exists = _exists(index), _exists(tmp)
    if tmp_exists and (not idx_exists or _has_search_all(index)):
        # Phase 2 was interrupted (or finished without cleanup): the temporary
        # copy is the complete source of truth.
        source_count = _count(tmp)
        if idx_exists and _count(index) == source_count:
            _request("DELETE", f"/{tmp}", None)
            log(f"{index}: already rebuilt, removed leftover copy")
            return {"index": index, "docs": source_count}
        if idx_exists:
            _request("DELETE", f"/{index}", None)  # partial rebuild
        log(f"{index}: resuming from {tmp}")
    else:
        source_count = _count(index)
        if tmp_exists:
            _request("DELETE", f"/{tmp}", None)  # partial copy; original intact
        _create_with_template_mapping(tmp, index)
        _reindex(index, tmp)
        if _count(tmp) != source_count:
            raise RuntimeError(f"{index}: copy has {_count(tmp)} docs, source has {source_count} — source kept")
        _request("DELETE", f"/{index}", None)
    _reindex(tmp, index)  # recreated by the fo-case-* template, now with search_all
    final = _count(index)
    if final != source_count:
        raise RuntimeError(f"{index}: rebuilt with {final} docs, expected {source_count} — copy kept in {tmp}")
    _request("DELETE", f"/{tmp}", None)
    log(f"{index}: {final} docs upgraded")
    return {"index": index, "docs": final}


def upgrade_case(case_id: str) -> dict:
    """Upgrade every legacy index of *case_id*. Runs to completion; returns a summary."""
    from config import get_redis

    r = get_redis()
    key = _status_key(case_id)
    lines: list[str] = []

    def log(msg: str) -> None:
        lines.append(f"{datetime.now(UTC).isoformat(timespec='seconds')} {msg}")
        r.set(key, json.dumps({"status": "running", "log": lines[-50:]}), ex=86400)

    pattern = f"fo-case-{case_id}-*"
    _SEARCH_ALL_CACHE.pop(pattern, None)
    _, legacy = search_all_indices(pattern)
    # Indices whose original was deleted by an interrupted run.
    for row in _request("GET", f"/_cat/indices/{TMP_PREFIX}{case_id}-*?format=json", None) or []:
        legacy.add("fo-case-" + row["index"][len(TMP_PREFIX):])
    done, failed = [], []
    for index in sorted(legacy):
        try:
            done.append(upgrade_index(index, log))
        except Exception as exc:  # noqa: BLE001 — record and continue with the next index
            logger.exception("search upgrade failed for %s", index)
            failed.append({"index": index, "error": str(exc)[:300]})
            log(f"{index}: FAILED — {exc}")
    _SEARCH_ALL_CACHE.pop(pattern, None)
    result = {"status": "failed" if failed else "done", "upgraded": done, "failed": failed, "log": lines[-50:]}
    r.set(key, json.dumps(result), ex=86400 * 7)
    return result


def start_upgrade(case_id: str) -> dict:
    """Start the upgrade in a background thread, unless ingest is in flight."""
    from config import get_redis

    active = active_ingest_jobs(case_id)
    if active:
        return {"status": "refused",
                "reason": f"{active} ingest job(s) still in flight — documents written during the copy "
                          "would be lost. Retry when ingestion has finished."}
    r = get_redis()
    if not r.set(_status_key(case_id) + ":lock", "1", nx=True, ex=6 * 3600):
        return {"status": "running", "reason": "an upgrade is already running for this case"}

    def run():
        try:
            upgrade_case(case_id)
        finally:
            r.delete(_status_key(case_id) + ":lock")

    r.set(_status_key(case_id), json.dumps({"status": "running", "log": []}), ex=86400)
    threading.Thread(target=run, name=f"search-upgrade-{case_id}", daemon=True).start()
    return {"status": "started"}


def upgrade_status(case_id: str) -> dict:
    from config import get_redis

    raw = get_redis().get(_status_key(case_id))
    st = json.loads(raw) if raw else {"status": "never"}
    with_f, legacy = search_all_indices(f"fo-case-{case_id}-*")
    st["indices_upgraded"] = len(with_f)
    st["indices_legacy"] = len(legacy)
    return st
