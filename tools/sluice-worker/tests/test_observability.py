"""Observability tests: Prometheus rendering + live /healthz /readyz /metrics."""

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import observability as obs  # noqa: E402


def test_prometheus_render():
    m = obs.Metrics()
    m.inc("events_total", 3, labels={"stage": "parse"}, help="events processed")
    m.inc("events_total", 2, labels={"stage": "parse"})
    m.gauge("queue_depth", 7, help="pending items")
    out = m.render_prometheus()
    assert "# TYPE events_total counter" in out
    assert 'events_total{stage="parse"} 5.0' in out
    assert "# TYPE queue_depth gauge" in out
    assert "queue_depth 7" in out


def test_health_server_endpoints():
    obs.METRICS.inc("test_metric", 1)
    server = obs.start_health_server(port=0, checks={"redis": lambda: True})
    port = server.server_address[1]
    try:

        def get(path):
            with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}") as r:
                return r.status, r.read().decode()

        s, body = get("/healthz")
        assert s == 200 and json.loads(body)["status"] == "ok"
        s, body = get("/readyz")
        assert s == 200 and json.loads(body)["checks"]["redis"] is True
        s, body = get("/metrics")
        assert s == 200 and "test_metric" in body
    finally:
        server.shutdown()


def test_readyz_degraded_on_failing_check():
    server = obs.start_health_server(port=0, checks={"es": lambda: False})
    port = server.server_address[1]
    try:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz")
            raise AssertionError("expected 503")
        except urllib.error.HTTPError as e:
            assert e.code == 503
    finally:
        server.shutdown()


def test_json_logging_setup():
    import io
    import logging

    obs.setup_json_logging()
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.setFormatter(obs._JsonFormatter())
    log = logging.getLogger("t")
    log.handlers[:] = [h]
    log.error("boom")
    rec = json.loads(buf.getvalue().strip())
    assert rec["level"] == "ERROR" and rec["msg"] == "boom" and rec["logger"] == "t"


class _FakeRedis:
    def __init__(self):
        self.streams = {}

    def xadd(self, key, fields, maxlen=None, approximate=True):
        self.streams.setdefault(key, []).append(fields)


def test_redis_log_handler_ships_to_capped_stream():
    import logging

    import time

    r = _FakeRedis()
    obs.attach_redis_logs("processor", r)
    log = logging.getLogger("citadel.test.redislog")
    log.error("disk pressure on node-3")
    key = obs.log_stream_key("processor")
    assert key == "citadel:logs:processor"
    # attach_redis_logs wraps the handler in a QueueListener (background thread),
    # so shipping is asynchronous — poll briefly for the drain instead of racing it.
    deadline = time.monotonic() + 3.0
    while not r.streams.get(key) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert r.streams.get(key), "nothing shipped to redis stream"
    entry = r.streams[key][-1]
    assert entry["svc"] == "processor" and entry["level"] == "ERROR"
    assert "disk pressure" in entry["line"]
    # detach so we don't leak the handler into other tests
    logging.getLogger().handlers = [
        h for h in logging.getLogger().handlers if not isinstance(h, obs.RedisLogHandler)
    ]


def test_redis_log_handler_never_raises_on_broken_redis():
    import logging

    class _Broken:
        def xadd(self, *a, **k):
            raise RuntimeError("redis down")

    h = obs.RedisLogHandler("processor", _Broken())
    # emit must swallow the error
    h.emit(logging.LogRecord("x", logging.INFO, __file__, 1, "msg", None, None))


if __name__ == "__main__":
    import urllib.error  # noqa: F401

    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        globals()[name]()
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
