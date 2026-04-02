"""SentinelMesh XDR – FastAPI application entry point."""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routes.agents import router as agents_router
from api.routes.alerts import router as alerts_router
from api.routes.analyze import router as analyze_router
from api.routes.correlation import router as correlation_router
from api.routes.incidents import router as incidents_router
from api.routes.ingest import router as ingest_router
from api.routes.logs import router as logs_router
from api.routes.memory import router as memory_router
from api.routes.monitoring import router as monitoring_router
from api.routes.rules import router as rules_router
from api.routes.simulate import router as simulate_router
from config import get_settings
from models.database import close_db, init_db
from utils.exceptions import SentinelMeshException, sentinelmesh_exception_handler
from utils.logging_config import configure_logging, get_logger
from utils.middleware import (
    CorrelationIDMiddleware,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)

settings = get_settings()
logger = get_logger(__name__)

# Monotonic timestamp recorded at startup to compute uptime
_startup_time: float | None = None


# ---------------------------------------------------------------------------
# Application lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _startup_time

    configure_logging(settings.log_level, settings.log_file)

    _startup_time = time.time()
    logger.info(
        "Starting SentinelMesh XDR",
        version=settings.app_version,
        environment=settings.environment,
    )

    await init_db()
    logger.info("Database initialised successfully")

    yield

    logger.info("Shutting down SentinelMesh XDR")
    await close_db()
    logger.info("Database connections closed")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SentinelMesh XDR",
    description=(
        "Extended Detection and Response Platform – "
        "real-time log ingestion, AI-driven threat detection, "
        "alert correlation and incident management."
    ),
    version=settings.app_version,
    docs_url=f"{settings.api_prefix}/docs",
    redoc_url=f"{settings.api_prefix}/redoc",
    openapi_url=f"{settings.api_prefix}/openapi.json",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Custom middleware
# Starlette wraps middleware as a stack, so the last `.add_middleware` call
# is the outermost layer.  We want the execution order to be:
#   CorrelationID → RequestLogging → RateLimit → SecurityHeaders → handler
# so we add them in reverse.
# ---------------------------------------------------------------------------

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    RateLimitMiddleware,
    requests_per_window=settings.rate_limit_requests,
    window_seconds=settings.rate_limit_window,
)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(CorrelationIDMiddleware)

# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------

app.add_exception_handler(SentinelMeshException, sentinelmesh_exception_handler)  # type: ignore[arg-type]


@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc: Exception) -> JSONResponse:
    logger.error(
        "Unhandled exception",
        exc_type=type(exc).__name__,
        error=str(exc),
        path=request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error_code": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred.",
            "details": None,
        },
    )


# ---------------------------------------------------------------------------
# System routes
# ---------------------------------------------------------------------------


@app.get(f"{settings.api_prefix}/health", tags=["System"], summary="Health check")
async def health_check() -> dict:
    """Return the operational status of the API and its dependencies."""
    from sqlalchemy import text

    from models.database import engine

    # Database probe
    db_status = "unknown"
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as exc:
        logger.error("Database health check failed", error=str(exc))
        db_status = "unhealthy"

    # Redis probe (best-effort – Redis is optional)
    redis_status = "unknown"
    try:
        import redis.asyncio as aioredis  # type: ignore[import]

        r = aioredis.from_url(settings.redis_url, socket_connect_timeout=1)
        await r.ping()
        await r.aclose()
        redis_status = "healthy"
    except Exception as exc:
        logger.warning("Redis health check failed", error=str(exc))
        redis_status = "unavailable"

    uptime = round(time.time() - _startup_time, 2) if _startup_time else 0.0
    overall = "healthy" if db_status == "healthy" else "degraded"

    return {
        "status": overall,
        "version": settings.app_version,
        "environment": settings.environment,
        "database": db_status,
        "redis": redis_status,
        "uptime_seconds": uptime,
    }


@app.get(f"{settings.api_prefix}/", tags=["System"], summary="API root")
async def root() -> dict:
    """Return basic API information."""
    return {
        "message": "SentinelMesh XDR API",
        "version": settings.app_version,
        "docs": f"{settings.api_prefix}/docs",
        "redoc": f"{settings.api_prefix}/redoc",
        "health": f"{settings.api_prefix}/health",
    }


# ---------------------------------------------------------------------------
# Feature routers
# ---------------------------------------------------------------------------

app.include_router(ingest_router, prefix=settings.api_prefix)
app.include_router(logs_router, prefix=settings.api_prefix)
app.include_router(analyze_router, prefix=settings.api_prefix)
app.include_router(alerts_router, prefix=settings.api_prefix)
app.include_router(incidents_router, prefix=settings.api_prefix)
app.include_router(simulate_router, prefix=settings.api_prefix)
app.include_router(agents_router, prefix=settings.api_prefix)
app.include_router(rules_router, prefix=settings.api_prefix)
app.include_router(memory_router, prefix=settings.api_prefix)
app.include_router(correlation_router, prefix=settings.api_prefix)
app.include_router(monitoring_router, prefix=settings.api_prefix)
