"""Health check endpoints for Kubernetes probes."""

import urllib.request

from fastapi import APIRouter

from config import settings

router = APIRouter(tags=["health"])


def _check_es() -> bool:
    try:
        with urllib.request.urlopen(f"{settings.ELASTICSEARCH_URL}/_cluster/health", timeout=3):
            return True
    except Exception:
        return False


def _check_redis() -> bool:
    try:
        from config import get_redis_with_timeout

        r = get_redis_with_timeout()
        return r.ping()
    except Exception:
        return False


@router.get("/health")
async def liveness():
    """Liveness probe — always 200 if the process is alive.

    Declared async so it runs directly on the event loop and answers instantly
    even when the sync threadpool is saturated by request load (heavy collab
    polling). A blocking sync handler here got starved past the probe timeout
    and the pod was killed despite being healthy.
    """
    return {"status": "ok"}


@router.get("/health/ready")
def readiness():
    """Readiness probe — checks ES and Redis connectivity."""
    es_ok = _check_es()
    redis_ok = _check_redis()
    status = "ready" if (es_ok and redis_ok) else "not_ready"
    return {
        "status": status,
        "elasticsearch": "ok" if es_ok else "unavailable",
        "redis": "ok" if redis_ok else "unavailable",
    }
