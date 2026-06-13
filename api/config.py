"""Application configuration via environment variables."""

import os


class Settings:
    # ── Infrastructure ─────────────────────────────────────────────────────
    ELASTICSEARCH_URL: str = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch-service:9200")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis-service:6379/0")
    MINIO_ENDPOINT: str = os.getenv("MINIO_ENDPOINT", "minio-service:9000")
    MINIO_ACCESS_KEY: str = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
    MINIO_SECRET_KEY: str = os.getenv("MINIO_SECRET_KEY", "minioadmin")
    MINIO_BUCKET: str = os.getenv("MINIO_BUCKET", "forensics-cases")
    PLUGINS_DIR: str = os.getenv("PLUGINS_DIR", "/app/babel")

    # ── Pagination ─────────────────────────────────────────────────────────
    DEFAULT_PAGE_SIZE: int = int(os.getenv("DEFAULT_PAGE_SIZE", "100"))
    MAX_PAGE_SIZE: int = int(os.getenv("MAX_PAGE_SIZE", "1000"))

    # ── Authentication ─────────────────────────────────────────────────────
    # Set AUTH_ENABLED=false to disable auth (dev/trusted-LAN only).
    AUTH_ENABLED: bool = os.getenv("AUTH_ENABLED", "true").lower() not in ("false", "0", "no")
    # Disabling auth grants every request a synthetic unrestricted admin — a total
    # bypass. Require an explicit second opt-in so it can never happen by a stray
    # env var in a real deploy; startup fails closed (re-enables auth) otherwise.
    ALLOW_NO_AUTH: bool = os.getenv("CITADEL_ALLOW_NO_AUTH", "false").lower() in (
        "true",
        "1",
        "yes",
    )
    # JWT_SECRET MUST be a strong random string in production.
    # Generate one: python -c "import secrets; print(secrets.token_hex(32))"
    JWT_SECRET: str = os.getenv("JWT_SECRET", "CHANGE_ME_IN_PRODUCTION")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_HOURS: int = int(os.getenv("JWT_EXPIRE_HOURS", "8"))

    # ── Sigma integration (opt-in) ─────────────────────────────────────────
    # When false: Sigma HQ community rules are not auto-seeded and the Sigma
    # parse/import/sync endpoints return 503. Native + custom rules are
    # unaffected — the platform works fully without Sigma.
    SIGMA_ENABLED: bool = os.getenv("SIGMA_ENABLED", "true").lower() not in ("false", "0", "no")

    # ── CORS ───────────────────────────────────────────────────────────────
    # Comma-separated list of allowed origins, or * for wildcard.
    # Example: ALLOWED_ORIGINS=https://citadel.example.com,https://citadel-dev.example.com
    # Default CLOSED: the UI is served same-origin (behind Traefik), so no CORS
    # is needed. Set ALLOWED_ORIGINS explicitly only for a separate-origin UI.
    ALLOWED_ORIGINS: list = [
        o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()
    ]

    # ── Licensing ──────────────────────────────────────────────────────────
    # Leave CITADEL_LICENSE_KEY empty to run in Community mode.
    CITADEL_LICENSE_KEY: str = os.getenv("CITADEL_LICENSE_KEY", "")
    CITADEL_LICENSE_SERVER: str = os.getenv("CITADEL_LICENSE_SERVER", "")
    CITADEL_LICENSE_JWT_SECRET: str = os.getenv("CITADEL_LICENSE_JWT_SECRET", "")

    # ── Bootstrap admin ────────────────────────────────────────────────────
    # Created automatically on first start if no users exist in Redis.
    # Change immediately after first login.
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "CitadelAdmin1!")


settings = Settings()

# ── Shared Redis connection pools ─────────────────────────────────────────────
# A single ConnectionPool is shared across the entire API process so that
# connections are reused across requests rather than opened/closed per call.
# All callers use get_redis() — the pool borrows a connection per operation
# and returns it automatically; no teardown code is needed.
import redis as _redis_lib

_redis_pool = _redis_lib.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=100,  # raised from 30 — ingest workers + UI polling can saturate a smaller pool
    decode_responses=True,
    socket_timeout=10,
    socket_connect_timeout=5,
)

# A separate pool with tight socket timeouts for health probes and metrics
# collection — these must never block for more than a few seconds.
_redis_timeout_pool = _redis_lib.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=20,
    decode_responses=True,
    socket_timeout=3,
    socket_connect_timeout=3,
)


def get_redis() -> _redis_lib.Redis:
    """Return a Redis client backed by the shared connection pool."""
    return _redis_lib.Redis(connection_pool=_redis_pool)


def get_redis_with_timeout() -> _redis_lib.Redis:
    """Return a Redis client with socket timeouts for health/metrics probes."""
    return _redis_lib.Redis(connection_pool=_redis_timeout_pool)
