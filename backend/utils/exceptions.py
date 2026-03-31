"""Custom exception hierarchy and FastAPI exception handlers for SentinelMesh XDR."""
from __future__ import annotations

from typing import Any, Optional

from fastapi import HTTPException


# ---------------------------------------------------------------------------
# Base exception
# ---------------------------------------------------------------------------


class SentinelMeshException(Exception):
    """Base exception for all SentinelMesh XDR application errors."""

    error_code: str = "SENTINELMESH_ERROR"
    http_status: int = 500

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        self.message = message
        self.details = details
        super().__init__(message)

    def to_http_exception(self) -> HTTPException:
        """Convert to a FastAPI :class:`~fastapi.HTTPException`."""
        return HTTPException(
            status_code=self.http_status,
            detail={
                "error_code": self.error_code,
                "message": self.message,
                "details": self.details,
            },
        )

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"error_code={self.error_code!r}, "
            f"message={self.message!r}, "
            f"details={self.details!r})"
        )


# ---------------------------------------------------------------------------
# Concrete exceptions
# ---------------------------------------------------------------------------


class NotFoundError(SentinelMeshException):
    """Raised when a requested resource does not exist."""

    error_code = "NOT_FOUND"
    http_status = 404


class AuthenticationError(SentinelMeshException):
    """Raised when authentication credentials are missing or invalid."""

    error_code = "AUTHENTICATION_FAILED"
    http_status = 401


class AuthorizationError(SentinelMeshException):
    """Raised when the authenticated user lacks permission for the operation."""

    error_code = "AUTHORIZATION_FAILED"
    http_status = 403


class LogIngestionError(SentinelMeshException):
    """Raised when a log ingestion request cannot be processed."""

    error_code = "LOG_INGESTION_ERROR"
    http_status = 422


class RuleValidationError(SentinelMeshException):
    """Raised when a detection rule fails structural or semantic validation."""

    error_code = "RULE_VALIDATION_ERROR"
    http_status = 400


class ThreatDetectionError(SentinelMeshException):
    """Raised when the threat-detection pipeline encounters an unrecoverable error."""

    error_code = "THREAT_DETECTION_ERROR"
    http_status = 500


class AgentError(SentinelMeshException):
    """Raised when communication with an external agent (e.g. Ollama) fails."""

    error_code = "AGENT_ERROR"
    http_status = 502


class CorrelationError(SentinelMeshException):
    """Raised when the event-correlation engine encounters an error."""

    error_code = "CORRELATION_ERROR"
    http_status = 500


class ValidationError(SentinelMeshException):
    """Raised when incoming data fails business-logic validation."""

    error_code = "VALIDATION_ERROR"
    http_status = 422


class RateLimitError(SentinelMeshException):
    """Raised when a client exceeds the configured request rate limit."""

    error_code = "RATE_LIMIT_EXCEEDED"
    http_status = 429


class DatabaseError(SentinelMeshException):
    """Raised when a database operation fails at the infrastructure level."""

    error_code = "DATABASE_ERROR"
    http_status = 503


# ---------------------------------------------------------------------------
# FastAPI exception handler
# ---------------------------------------------------------------------------


async def sentinelmesh_exception_handler(request: Any, exc: SentinelMeshException):  # type: ignore[override]
    """Register this handler with FastAPI to serialize :class:`SentinelMeshException`
    subclasses into consistent JSON error responses.

    Usage::

        app.add_exception_handler(SentinelMeshException, sentinelmesh_exception_handler)
    """
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=exc.http_status,
        content={
            "error_code": exc.error_code,
            "message": exc.message,
            "details": exc.details,
        },
    )
