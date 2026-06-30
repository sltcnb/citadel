"""Citadel API — FastAPI entrypoint."""

import asyncio
import collections
import json
import logging
import os
import time

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

# ── API request telemetry ─────────────────────────────────────────────────────
# Rolling window of (duration_ms, status_code) tuples for the last 2000 requests.
# Stored at module level so middleware and the metrics endpoint share it directly.
_REQUEST_WINDOW: collections.deque = collections.deque(maxlen=2000)
_REQUEST_TOTALS = {"count": 0, "errors": 0}  # monotonic counters, never reset

import redis_keys as rk
from auth.dependencies import require_admin, require_analyst_or_admin, require_developer_or_admin
from license.router import router as license_router
from routers import (
    admin_logs,
    admin_utils,
    alert_rules,
    anomaly,
    audit,
    baseline,
    case_files,
    case_templates,
    cases,
    collab,
    collector,
    companies,
    cti,
    editor,
    entity_graph,
    evidence_seal,
    export,
    findings,
    global_alert_rules,
    groups,
    harvest,
    health,
    ingest,
    internal_chain,
    jobs,
    killchain,
    llm_config,
    metrics,
    modules,
    notes,
    pilot_memory,
    pilot_settings,
    platform_settings,
    plugins,
    process_tree,
    reports,
    s3_integration,
    saved_searches,
    search,
    sigma_sync,
    sso,
    tools as tools_router,
    watchlist,
    webhooks,
    yara_rules,
)
from routers import auth as auth_router

from config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _bootstrap_admin() -> None:
    """
    Called at startup to:
    1. Migrate pre-RBAC user accounts that lack a 'role' field → promote to admin.
    2. Create a default admin user from env vars if Redis has no users at all.

    This is idempotent — safe to run on every restart.
    """
    from auth.service import (
        _USER_KEY,
        _USERS_SET,
        create_user,
        user_count,
    )
    from auth.service import (
        _redis as auth_redis,
    )

    try:
        r = auth_redis()

        # ── Step 1: patch existing users without a role (pre-RBAC migration) ──
        usernames = r.smembers(_USERS_SET)
        for username in usernames:
            key = _USER_KEY.format(username=username)
            if not r.hget(key, "role"):
                r.hset(key, "role", "admin")
                logger.info("Bootstrap: migrated user '%s' → role=admin", username)

        # ── Step 2: seed default admin if no users exist ───────────────────────
        if user_count() == 0:
            try:
                create_user(settings.ADMIN_USERNAME, settings.ADMIN_PASSWORD, role="admin")
                # If the bootstrap admin still uses the shipped default password,
                # force a change on first login — a full token is withheld until
                # the password is rotated (see /auth/login + /auth/login/change-password).
                if settings.ADMIN_PASSWORD == "CitadelAdmin1!":
                    from auth.service import set_must_change_password

                    set_must_change_password(settings.ADMIN_USERNAME, True)
                logger.info(
                    "Bootstrap: created default admin user '%s'. "
                    "Change the password immediately after first login.",
                    settings.ADMIN_USERNAME,
                )
            except ValueError:
                pass  # Already exists (race between replicas)
    except Exception as exc:
        # Redis may not be reachable during very early startup; the readinessProbe
        # ensures requests only arrive after Redis is up, so this is non-fatal.
        logger.warning("Bootstrap admin failed (Redis not ready?): %s", exc)


app = FastAPI(
    title="Citadel API",
    description="Kubernetes-native digital forensics analysis platform",
    version="1.0.0",
    # Serve the interactive docs UNDER the routed /api/v1 prefix. The ingress
    # only forwards /api → the API service (no prefix strip), so the default
    # app-root /docs and /openapi.json are unreachable behind a FQDN. Mounting
    # them here makes Swagger work on any host without an ingress change.
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_url="/api/v1/openapi.json",
)

# ── Global exception handler ──────────────────────────────────────────────────
# Catches anything that escapes FastAPI's built-in handlers (e.g. exceptions
# thrown inside middleware before the router runs, or errors during ASGI
# lifecycle) and ensures the response is always valid JSON — never plain text.


@app.exception_handler(Exception)
async def _unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    # Log full detail server-side; return only a generic message + correlation id
    # to the client (don't leak stack traces, paths, dependency versions).
    import uuid as _uuid
    corr = _uuid.uuid4().hex[:12]
    logger.exception("Unhandled exception [%s] on %s %s", corr, request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "correlation_id": corr},
    )


async def _redis_unavailable(request: Request, exc: Exception) -> JSONResponse:
    logger.warning("Redis unavailable on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(
        status_code=503,
        content={"detail": "Service temporarily unavailable — Redis is unreachable"},
    )


from datetime import UTC

import redis as _redis_lib  # noqa: E402

app.add_exception_handler(_redis_lib.exceptions.ConnectionError, _redis_unavailable)
app.add_exception_handler(_redis_lib.exceptions.TimeoutError, _redis_unavailable)

# ── Middleware ─────────────────────────────────────────────────────────────────

_GUEST_WRITE_ALLOW = (
    # Guests can self-serve case creation + the things they need to work inside their cases.
    ("POST", "/api/v1/cases"),
    ("POST", "/api/v1/cases/"),
)
_GUEST_PATH_PREFIX_ALLOW = (
    # Within a case they own, allow notes/tags/flags, file ingestion, module runs.
    # Cross-case admin operations stay blocked because they don't match these prefixes.
    "/api/v1/cases/",
)


def _guest_path_allowed(method: str, path: str) -> bool:
    if (method, path) in _GUEST_WRITE_ALLOW:
        return True
    # case-scoped write (anything under /api/v1/cases/{id}/…) — guests opted in
    if method in ("POST", "PUT", "PATCH", "DELETE") and any(
        path.startswith(p) and "/" in path[len(p) :] for p in _GUEST_PATH_PREFIX_ALLOW
    ):
        return True
    return False


# High-frequency polling paths — skipped so the access log shows meaningful
# orchestration, not a flood of heartbeats.
_ACCESS_LOG_SKIP = (
    "/health", "/collab/", "/ai/agent/active", "/ai/results",
    "/metrics/dashboard", "/metrics/history", "/jobs",
    # The log viewer itself + the capability poll — logging these floods the
    # stream with the viewer's own traffic.
    "/admin/logs", "/tools/capabilities", "/cti/iocs/stats", "/license/info",
)
_access_logger = logging.getLogger("citadel.api")

# ── Audit trail (chain-of-custody) ─────────────────────────────────────────────
# Record an immutable, hash-chained audit event for MUTATING requests on the API.
# Skip read-only methods (GET/HEAD/OPTIONS) and pure health/metrics noise — but
# DO record logins/logouts and every case/evidence mutation.
import re as _re

_AUDIT_METHODS = ("POST", "PUT", "PATCH", "DELETE")
# Health/metrics churn that carries no chain-of-custody value.
_AUDIT_SKIP = ("/health", "/metrics/dashboard", "/metrics/history")
_CASE_ID_RE = _re.compile(r"/cases/([^/]+)")


def _audit_actor_from_scope(scope) -> tuple[str, str]:
    """Best-effort (actor, role) from the bearer / ?_token, without raising.
    Returns ("anonymous", "") when no valid token is present."""
    token = ""
    for k, v in scope.get("headers", []):
        if k == b"authorization":
            hv = v.decode("latin-1")
            if hv.startswith("Bearer "):
                token = hv[7:]
            break
    if not token:
        # ?_token query param (browser downloads / EventSource).
        qs = scope.get("query_string", b"").decode("latin-1")
        from urllib.parse import parse_qs

        token = (parse_qs(qs).get("_token") or [""])[0]
    if not token:
        return "anonymous", ""
    try:
        from auth.service import decode_token

        payload = decode_token(token)
        return payload.get("sub") or "anonymous", payload.get("role") or ""
    except Exception:  # noqa: BLE001 — never let token decode break auditing
        return "anonymous", ""


def _client_ip_from_scope(scope) -> str:
    for k, v in scope.get("headers", []):
        if k == b"x-forwarded-for":
            return v.decode("latin-1").split(",")[0].strip()
    client = scope.get("client")
    return client[0] if client else ""


def _record_audit(scope, method: str, path: str, status_code: int) -> None:
    """Synchronous audit write — called off the event loop via run_in_executor.
    Wrapped so an audit failure can never affect the request it describes."""
    try:
        actor, role = _audit_actor_from_scope(scope)
        m = _CASE_ID_RE.search(path)
        case_id = m.group(1) if m else ""
        from services import audit as _audit

        _audit.record_event(
            actor=actor, role=role, method=method, path=path,
            case_id=case_id, status=status_code, ip=_client_ip_from_scope(scope),
        )
    except Exception as exc:  # noqa: BLE001 — auditing must never break a request
        logger.warning("audit: failed to record %s %s: %s", method, path, exc)

_SECURITY_HEADERS = {
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    b"referrer-policy": b"strict-origin-when-cross-origin",
}


class CoreHTTPMiddleware:
    """One pure-ASGI middleware in place of four BaseHTTPMiddleware layers.

    BaseHTTPMiddleware raises ``RuntimeError("No response returned.")`` when a
    client disconnects mid-request — the Logs page aborts its poll on every
    navigation, which spammed that traceback — and each layer adds a per-request
    anyio task group. Folding the guest read-only guard, security headers,
    telemetry and access logging into a single ASGI middleware is
    disconnect-safe and cheaper per request.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        path = scope.get("path", "")

        # ── Guest read-only guard (short-circuit before hitting the route) ────
        if method not in ("GET", "HEAD", "OPTIONS"):
            denied = self._guest_denied(scope, method, path)
            if denied is not None:
                await denied(scope, receive, send)
                return

        start = time.perf_counter()
        status = {"code": 0}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
                headers = message.setdefault("headers", [])
                for k, v in _SECURITY_HEADERS.items():
                    headers.append((k, v))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            ms = round((time.perf_counter() - start) * 1000, 1)
            code = status["code"]
            try:
                _REQUEST_WINDOW.append((ms, code))
                _REQUEST_TOTALS["count"] += 1
                if code >= 500:
                    _REQUEST_TOTALS["errors"] += 1
            except Exception:  # noqa: BLE001
                pass
            try:
                if code and "/api/v1/" in path and not any(s in path for s in _ACCESS_LOG_SKIP):
                    short = path.split("/api/v1/", 1)[-1]
                    _access_logger.info("%s /%s → %d (%.0fms)", method, short, code, ms)
            except Exception:  # noqa: BLE001 — logging must never break a request
                pass
            # ── Persistent audit trail — mutating API requests only ───────────
            # Offload the Redis/ES write to the threadpool so the chain append
            # never blocks the event loop, and never let it raise here.
            try:
                if (
                    code
                    and method in _AUDIT_METHODS
                    and "/api/v1/" in path
                    and not any(s in path for s in _AUDIT_SKIP)
                ):
                    loop = asyncio.get_event_loop()
                    loop.run_in_executor(
                        None, _record_audit, scope, method, path, code
                    )
            except Exception:  # noqa: BLE001 — auditing must never break a request
                pass

    @staticmethod
    def _guest_denied(scope, method, path):
        auth_header = ""
        for k, v in scope.get("headers", []):
            if k == b"authorization":
                auth_header = v.decode("latin-1")
                break
        if not auth_header.startswith("Bearer "):
            return None
        try:
            from auth.service import decode_token

            if settings.AUTH_ENABLED:
                payload = decode_token(auth_header[7:])
                if payload.get("role") == "guest" and not _guest_path_allowed(method, path):
                    return JSONResponse(
                        status_code=403,
                        content={
                            "detail": "Guest accounts can create cases and work inside them, but cannot touch platform settings."
                        },
                    )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Token decode error in guest guard (ignoring): %s", exc)
        return None


# Innermost custom layer (added first → GZip/CORS wrap it).
app.add_middleware(CoreHTTPMiddleware)

app.add_middleware(GZipMiddleware, minimum_size=1024)

_wildcard_origins = settings.ALLOWED_ORIGINS == ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    # credentials=True is incompatible with wildcard origins per CORS spec;
    # only enable when specific origins are configured.
    allow_credentials=not _wildcard_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)




# ── Startup hook ─────────────────────────────────────────────────────────────


async def _metrics_background_loop():
    """Collect and persist a slim metrics snapshot every 30 s, forever."""
    import asyncio as _aio

    # Small initial delay so services are fully up before first scrape
    await _aio.sleep(10)
    while True:
        try:
            # Run the blocking collection in a thread so the event loop stays free
            await _aio.get_event_loop().run_in_executor(None, metrics.store_metrics_snapshot)
        except Exception as exc:
            logger.warning("Metrics snapshot failed: %s", exc)
        await _aio.sleep(30)


async def _auto_archive_loop():
    import asyncio
    from datetime import datetime, timedelta

    while True:
        await asyncio.sleep(3600)
        try:
            from config import get_redis

            r = get_redis()
            raw = r.get(rk.ARCHIVE_SETTINGS)
            if not raw:
                continue
            cfg = json.loads(raw)
            if not cfg.get("auto_archive_enabled"):
                continue
            days = int(cfg.get("auto_archive_days", 14))
            cutoff = datetime.now(UTC) - timedelta(days=days)
            case_ids = r.smembers("cases:all") or set()
            for cid in case_ids:
                try:
                    case = r.hgetall(f"case:{cid}")
                    if not case or case.get("status") != "active":
                        continue
                    updated = case.get("updated_at") or case.get("created_at")
                    if not updated:
                        continue
                    dt = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=UTC)
                    if dt < cutoff:
                        if cfg.get("auto_export_enabled"):
                            from routers import export as export_router

                            export_router.purge_archive_case(cid)
                        else:
                            r.hset(
                                f"case:{cid}",
                                mapping={
                                    "status": "archived",
                                    "updated_at": datetime.now(UTC).isoformat(),
                                },
                            )
                except Exception as e:
                    import logging as _logging

                    _logging.getLogger(__name__).warning(
                        "Auto-archive failed for case %s: %s", cid, e
                    )
        except Exception as exc:
            logger.exception("Auto-archive loop error: %s", exc)


@app.on_event("startup")
async def _on_startup():
    # Ship the API's structured logs to Redis so the admin console can tail them
    # (citadel:logs:api). Best-effort — never block startup on it.
    try:
        from citadel_contracts import attach_redis_logs
        from config import get_redis
        attach_redis_logs("api", get_redis())
        # Dedicated "tools" stream — the tool↔Citadel orchestration choreography
        # (announcements, capability requests, finalize chain) in one place.
        import logging as _lg

        from citadel_contracts.logship import RedisLogHandler, _async_handler
        _tools_log = _lg.getLogger("citadel.tools")
        if not any(getattr(h, "_listener", None) for h in _tools_log.handlers):
            _tools_log.addHandler(_async_handler(RedisLogHandler("tools", get_redis())))
        _tools_log.setLevel(_lg.INFO)  # propagates to api stream too
    except Exception as exc:
        logger.warning("admin log shipping unavailable: %s", exc)

    if not settings.AUTH_ENABLED and not settings.ALLOW_NO_AUTH:
        # AUTH_ENABLED=false makes every request a synthetic unrestricted admin.
        # That's only acceptable behind an explicit second opt-in. Fail CLOSED:
        # re-enable auth for this process rather than silently serving wide open.
        settings.AUTH_ENABLED = True
        logger.critical(
            "SECURITY: AUTH_ENABLED=false but CITADEL_ALLOW_NO_AUTH is not set — "
            "refusing to run without authentication. Auth has been force-enabled "
            "for this process. Set CITADEL_ALLOW_NO_AUTH=true to intentionally "
            "disable auth (dev / trusted-LAN only)."
        )

    if settings.AUTH_ENABLED:
        if settings.JWT_SECRET in ("CHANGE_ME_IN_PRODUCTION", ""):
            # Never run with the KNOWN default (anyone could forge an admin token).
            # But don't hard-crash a running deploy either — generate a strong
            # RANDOM ephemeral secret for this process. Tokens reset on restart
            # (users re-login); set JWT_SECRET in the env to persist sessions.
            import secrets as _secrets
            settings.JWT_SECRET = _secrets.token_hex(32)
            logger.critical(
                "SECURITY: JWT_SECRET was unset/default — generated a random ephemeral "
                "secret for this process. Tokens will not survive a restart. Set a "
                "persistent JWT_SECRET env var in production."
            )
        if settings.ADMIN_PASSWORD == "CitadelAdmin1!":
            logger.warning(
                "SECURITY: ADMIN_PASSWORD is set to the default value. "
                "Change it immediately after first login."
            )
    if settings.MINIO_ACCESS_KEY == "minioadmin" and settings.MINIO_SECRET_KEY == "minioadmin":
        logger.warning(
            "SECURITY: MinIO is using default credentials (minioadmin/minioadmin). "
            "Set MINIO_ACCESS_KEY / MINIO_SECRET_KEY to protect evidence storage."
        )
    _bootstrap_admin()
    asyncio.create_task(cti.start_cti_scheduler())
    asyncio.create_task(_metrics_background_loop())
    asyncio.create_task(_auto_archive_loop())
    try:
        from services.elasticsearch import ensure_artifacts_index

        ensure_artifacts_index()
    except Exception as _startup_exc:
        logger.warning("Could not ensure fo-artifacts index at startup: %s", _startup_exc)

    # Log the tool capability declarations so the admin console (Tool Logs)
    # shows what each tool advertised when plugged in — live confirmation of the
    # declaration → UI contract.
    try:
        from routers.tools import _aggregate

        # Seed Redis from the baked-in manifests. Only LOG an announce when a
        # tool's manifest is new or changed — otherwise every restart would
        # repeat the same announcements and spam the orchestration log.
        import json as _json
        import logging as _lg2

        from citadel_contracts import capabilities_redis_key, register_capability
        from routers.tools import _from_filesystem

        _tlog = _lg2.getLogger("citadel.tools")
        _r = get_redis()
        changed = []
        for _doc in _from_filesystem().values():
            tool = _doc.get("tool")
            new_json = _json.dumps(_doc, sort_keys=True)
            try:
                prev = _r.get(capabilities_redis_key(tool))
                prev = prev.decode() if isinstance(prev, bytes) else prev
            except Exception:
                prev = None
            is_changed = (prev is None) or (
                _json.dumps(_json.loads(prev), sort_keys=True) != new_json
                if prev else True
            )
            register_capability(_r, _doc)
            if is_changed:
                changed.append(_doc)

        if changed:
            _tlog.info("[citadel] %d tool manifest(s) new/updated this boot", len(changed))
            for m in changed:
                caps = ", ".join(c.get("key", "") for c in m.get("capabilities", []))
                _tlog.info(
                    "[%s → citadel] announced: v%s [%s] → %s",
                    m["tool"], m.get("version", "?"),
                    ",".join(m.get("platforms", [])) or "any", caps or "(none)",
                )
        else:
            _tlog.info("[citadel] %d tool(s) already registered (no manifest changes)",
                       len(_from_filesystem()))
        for m in _aggregate():
            for w in m.get("warnings", []):
                logger.warning("capability manifest warning: %s", w)
    except Exception as _cap_exc:
        logger.warning("Could not load tool capability manifests: %s", _cap_exc)


# ── Auth dependencies for route protection ────────────────────────────────────
# Health and auth endpoints are public; everything else requires a valid JWT.
# analyst_or_admin: all 4 roles allowed; guest write-blocking enforced by middleware
# developer_or_admin: Studio routes — developer and admin only
# admin_only: system configuration
_analyst_or_admin = [Depends(require_analyst_or_admin)]
_developer_or_admin = [Depends(require_developer_or_admin)]
_admin_only = [Depends(require_admin)]

# ── Routers ────────────────────────────────────────────────────────────────────

# Public — no auth required
app.include_router(health.router, prefix="/api/v1")
app.include_router(auth_router.router, prefix="/api/v1")
app.include_router(sso.router, prefix="/api/v1")  # OIDC SSO — endpoints are public by design (browser redirects)
app.include_router(sso.admin_router, prefix="/api/v1")  # SSO admin config — gated by require_admin
app.include_router(license_router, prefix="/api/v1")

# RBAC group/permission management (gated inside the router via require_permission)
app.include_router(groups.router, prefix="/api/v1")
app.include_router(groups.catalog_router, prefix="/api/v1")

# Protected — analyst or admin
app.include_router(cases.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(ingest.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(jobs.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(search.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(plugins.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(tools_router.router, prefix="/api/v1", dependencies=_analyst_or_admin)
# Internal service chain — own token auth (NOT user auth); in-cluster only.
app.include_router(internal_chain.router, prefix="/api/v1")
app.include_router(saved_searches.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(notes.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(alert_rules.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(export.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(modules.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(collector.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(editor.router, prefix="/api/v1", dependencies=_developer_or_admin)
app.include_router(cti.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(watchlist.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(reports.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(anomaly.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(findings.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(process_tree.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(baseline.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(entity_graph.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(killchain.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(pilot_memory.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(evidence_seal.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(case_templates.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(collab.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(yara_rules.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(case_files.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(harvest.router, prefix="/api/v1", dependencies=_analyst_or_admin)

# Protected — analyst or admin (alert rules used by analysts too)
app.include_router(global_alert_rules.router, prefix="/api/v1", dependencies=_analyst_or_admin)

# Protected — admin only (system configuration)
# llm_config is registered with analyst_or_admin so analysts can use AI analysis.
# The /admin/llm-config CRUD routes carry their own require_admin dependency.
app.include_router(llm_config.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(s3_integration.router, prefix="/api/v1", dependencies=_admin_only)
app.include_router(admin_utils.router, prefix="/api/v1", dependencies=_admin_only)
app.include_router(admin_logs.router, prefix="/api/v1", dependencies=_admin_only)
app.include_router(platform_settings.router, prefix="/api/v1")
app.include_router(pilot_settings.router, prefix="/api/v1")
app.include_router(webhooks.router, prefix="/api/v1", dependencies=_admin_only)
app.include_router(companies.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(metrics.router, prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(sigma_sync.router, prefix="/api/v1", dependencies=_admin_only)
app.include_router(audit.router, prefix="/api/v1", dependencies=_admin_only)
