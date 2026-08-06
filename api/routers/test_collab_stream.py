"""Collab SSE stream must not block the event loop.

redis-py's ``pubsub.get_message(timeout=…)`` is a blocking call; the stream
generator must dispatch it via ``asyncio.to_thread`` so concurrent viewers
don't stall the loop. Pub/sub is mocked — no Redis needed.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import routers.collab as collab  # noqa: E402


class _FakePubSub:
    def __init__(self, message=None):
        self._message = message
        self.closed = False

    def subscribe(self, channel):
        pass

    def get_message(self, ignore_subscribe_messages=True, timeout=None):
        return self._message

    def unsubscribe(self, channel):
        pass

    def close(self):
        self.closed = True


class _FakeRedis:
    def __init__(self, pubsub):
        self._pubsub = pubsub

    def lrange(self, key, start, end):
        return []

    def pubsub(self):
        return self._pubsub


class _FakeRequest:
    """Disconnects after `disconnect_after` checks."""

    def __init__(self, disconnect_after=2):
        self._checks = 0
        self._disconnect_after = disconnect_after

    async def is_disconnected(self):
        self._checks += 1
        return self._checks > self._disconnect_after


def test_get_message_runs_in_thread(monkeypatch):
    """The blocking get_message must go through asyncio.to_thread."""
    pubsub = _FakePubSub({"type": "message", "data": b'{"type": "presence"}'})
    monkeypatch.setattr(collab, "get_redis", lambda: _FakeRedis(pubsub))

    to_thread_calls: list = []
    real_to_thread = asyncio.to_thread

    async def _spy(fn, *args, **kwargs):
        to_thread_calls.append(fn)
        return await real_to_thread(fn, *args, **kwargs)

    monkeypatch.setattr(collab.asyncio, "to_thread", _spy)

    async def _run():
        chunks = []
        async for chunk in collab._stream("case1", _FakeRequest(disconnect_after=1)):
            chunks.append(chunk)
        return chunks

    chunks = asyncio.run(_run())

    assert chunks == [b'data: {"type": "presence"}\n\n']
    assert to_thread_calls, "get_message must be dispatched via asyncio.to_thread"
    assert any(getattr(fn, "__self__", None) is pubsub for fn in to_thread_calls)
    assert pubsub.closed  # finally-block cleanup ran


def test_quiet_channel_yields_nothing_and_cleans_up(monkeypatch):
    pubsub = _FakePubSub(message=None)
    monkeypatch.setattr(collab, "get_redis", lambda: _FakeRedis(pubsub))

    async def _run():
        return [chunk async for chunk in collab._stream("case1", _FakeRequest())]

    assert asyncio.run(_run()) == []
    assert pubsub.closed
