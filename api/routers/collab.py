"""
Live collaboration — Server-Sent Events stream of case activity.

Two surfaces:
  - POST  /cases/{case_id}/collab/event   — publish (presence, flag, pin, note)
  - GET   /cases/{case_id}/collab/stream  — SSE stream of recent + new events

Backed by a Redis list (last 200 events) + Pub/Sub channel for fan-out.
No persistent storage beyond Redis — collaboration is ephemeral signal,
not an audit log.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncGenerator

from auth.dependencies import get_current_user
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from services.cases import get_case

from config import get_redis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["collab"])

_LIST_MAX = 200
_TTL_SECONDS = 7 * 86400
_HEARTBEAT_S = 25  # send a comment line every N seconds to keep connection alive


def _list_key(case_id: str) -> str:
    return f"fo:collab:list:{case_id}"


def _chan_key(case_id: str) -> str:
    return f"fo:collab:chan:{case_id}"


@router.post("/cases/{case_id}/collab/event")
def publish_collab_event(case_id: str, body: dict, user: dict = Depends(get_current_user)):
    """Publish a collab event. body = {type, payload, target?}.

    Common types:
      - presence  → 'I am here'
      - flag      → {fo_id, is_flagged}
      - pin       → {fo_id, is_pinned}
      - note      → {fo_id, snippet}
      - search    → {query}
    """
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    ev = {
        "ts": time.time(),
        "user": user.get("username", ""),
        "type": body.get("type", "event"),
        "payload": body.get("payload", {}),
    }
    r = get_redis()
    s = json.dumps(ev)
    pipe = r.pipeline(transaction=False)
    pipe.lpush(_list_key(case_id), s)
    pipe.ltrim(_list_key(case_id), 0, _LIST_MAX - 1)
    pipe.expire(_list_key(case_id), _TTL_SECONDS)
    pipe.publish(_chan_key(case_id), s)
    pipe.execute()
    return {"ok": True}


async def _stream(case_id: str, request: Request) -> AsyncGenerator[bytes, None]:
    r = get_redis()
    # 1) Initial backlog (oldest → newest)
    backlog = r.lrange(_list_key(case_id), 0, _LIST_MAX - 1) or []
    for raw in reversed(backlog):
        s = raw.decode() if isinstance(raw, bytes) else raw
        yield f"data: {s}\n\n".encode()
    # 2) Live tail via pub/sub
    pubsub = r.pubsub()
    pubsub.subscribe(_chan_key(case_id))
    last_beat = time.monotonic()
    try:
        while True:
            if await request.is_disconnected():
                break
            msg = pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg and msg.get("type") == "message":
                data = msg.get("data")
                if isinstance(data, bytes):
                    data = data.decode()
                yield f"data: {data}\n\n".encode()
                last_beat = time.monotonic()
            elif time.monotonic() - last_beat > _HEARTBEAT_S:
                yield b": ping\n\n"
                last_beat = time.monotonic()
            await asyncio.sleep(0.1)
    finally:
        try:
            pubsub.unsubscribe(_chan_key(case_id))
            pubsub.close()
        except Exception:
            pass


@router.get("/cases/{case_id}/collab/stream")
async def collab_stream(case_id: str, request: Request, _: dict = Depends(get_current_user)):
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return StreamingResponse(
        _stream(case_id, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable proxy buffering (Traefik / nginx)
        },
    )


@router.get("/cases/{case_id}/collab/recent")
def recent_events(case_id: str, _: dict = Depends(get_current_user)):
    """Plain JSON fetch of the backlog (for clients without SSE)."""
    raw = get_redis().lrange(_list_key(case_id), 0, _LIST_MAX - 1) or []
    events = []
    for r in raw:
        try:
            events.append(json.loads(r.decode() if isinstance(r, bytes) else r))
        except Exception:
            continue
    return {"events": events}
