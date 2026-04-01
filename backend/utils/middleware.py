"""FastAPI / Starlette middleware for SentinelMesh XDR."""
from __future__ import annotations

import time
import uuid
from collections import defaultdict
from typing import Dict, List

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from utils.logging_config import get_logger

_logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Correlation-ID middleware
# ---------------------------------------------------------------------------


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """Propagate or generate a ``X-Correlation-ID`` header on every request."""

    async def dispatch(self, request: Request, call_next):
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        request.state.correlation_id = correlation_id

        # Make available to structlog context as well
        from utils.logging_config import set_correlation_id
        set_correlation_id(correlation_id)

        response: Response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response


# ---------------------------------------------------------------------------
# Request-logging middleware
# ---------------------------------------------------------------------------


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every inbound request and its response with timing information."""

    async def dispatch(self, request: Request, call_next):
        start_time = time.perf_counter()
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        from utils.logging_config import set_request_id
        set_request_id(request_id)

        _logger.info(
            "request received",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            query=str(request.url.query),
            client=request.client.host if request.client else "unknown",
        )

        response: Response = await call_next(request)

        duration_ms = (time.perf_counter() - start_time) * 1000
        _logger.info(
            "request completed",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round(duration_ms, 3),
        )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"
        return response


# ---------------------------------------------------------------------------
# Rate-limit middleware
# ---------------------------------------------------------------------------


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Token-bucket style rate limiter keyed by client IP address.

    Defaults to 100 requests per 60-second sliding window.

    .. note::
        This implementation uses an **in-process** dictionary and is suitable
        for single-worker deployments or development.  In a multi-worker or
        distributed production environment, replace the backing store with
        Redis (e.g. using ``redis.asyncio``) to share state across processes.
    """

    def __init__(
        self,
        app: ASGIApp,
        requests_per_window: int = 100,
        window_seconds: int = 60,
    ) -> None:
        super().__init__(app)
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        # Maps client_id → sorted list of request timestamps (epoch seconds)
        self._request_counts: Dict[str, List[float]] = defaultdict(list)

    def _get_client_id(self, request: Request) -> str:
        """Resolve the client identifier from ``X-Forwarded-For`` or ``client.host``."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next):
        client_id = self._get_client_id(request)
        now = time.time()

        # Evict timestamps outside the current window
        self._request_counts[client_id] = [
            t for t in self._request_counts[client_id]
            if now - t < self.window_seconds
        ]

        if len(self._request_counts[client_id]) >= self.requests_per_window:
            _logger.warning(
                "rate limit exceeded",
                client_id=client_id,
                path=request.url.path,
                window_seconds=self.window_seconds,
                limit=self.requests_per_window,
            )
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=429,
                content={
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "message": "Too many requests. Please slow down.",
                },
                headers={
                    "Retry-After": str(self.window_seconds),
                    "X-RateLimit-Limit": str(self.requests_per_window),
                    "X-RateLimit-Window": str(self.window_seconds),
                },
            )

        self._request_counts[client_id].append(now)
        return await call_next(request)


# ---------------------------------------------------------------------------
# Security-headers middleware
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach standard security headers to every response."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'"
        )
        return response
