"""Admin dead-letter queue viewer + replay.

Surfaces the poison-task list the Sluice worker parks failed jobs on after
exhausting retries (tools/sluice/worker/robustness.py) so an operator can see
what died and re-enqueue it without shelling into Redis. Replay is idempotent
— see services/dead_letter.py for the "already succeeded" guard.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query
from services import dead_letter

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin"])


@router.get("/admin/dead-letter")
def list_dead_letter(limit: int = Query(200, ge=1, le=1000)):
    """List dead-lettered tasks, newest first."""
    entries = dead_letter.list_dead_letters(limit=limit)
    return {"count": len(entries), "total": dead_letter.dead_letter_count(), "entries": entries}


@router.post("/admin/dead-letter/{index}/replay")
def replay_dead_letter(index: int):
    """Re-enqueue the dead-letter entry at *index* (0 = newest) and clear it.

    A no-op (still clears the entry) when the job it belongs to already
    reached a terminal successful state.
    """
    try:
        result = dead_letter.replay_entry(index)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("dead-letter replay failed for index %d", index)
        raise HTTPException(status_code=503, detail=f"Replay failed: {exc}") from exc
    return result


@router.post("/admin/dead-letter/replay-all")
def replay_all_dead_letter():
    """Re-enqueue every dead-lettered entry (idempotency guard applies to each)."""
    results = dead_letter.replay_all()
    requeued = sum(1 for r in results if r["status"] == "requeued")
    skipped = sum(1 for r in results if r["status"] == "skipped_already_processed")
    return {"replayed": requeued, "skipped_already_processed": skipped, "results": results}
