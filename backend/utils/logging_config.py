"""Enterprise-grade structured logging configuration using structlog."""
from __future__ import annotations

import logging
import logging.handlers
import os
import time
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
from typing import Any, Callable

import structlog
from structlog.types import EventDict, WrappedLogger

# ---------------------------------------------------------------------------
# Context variables – set per-request, accessible throughout the call stack
# ---------------------------------------------------------------------------

_request_id_var: ContextVar[str] = ContextVar("request_id", default="-")
_user_id_var: ContextVar[str] = ContextVar("user_id", default="-")
_correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="-")


def set_request_id(value: str) -> None:
    _request_id_var.set(value)


def set_user_id(value: str) -> None:
    _user_id_var.set(value)


def set_correlation_id(value: str) -> None:
    _correlation_id_var.set(value)


def get_request_id() -> str:
    return _request_id_var.get()


def get_user_id() -> str:
    return _user_id_var.get()


def get_correlation_id() -> str:
    return _correlation_id_var.get()


# ---------------------------------------------------------------------------
# Custom structlog processors
# ---------------------------------------------------------------------------


def _inject_context_vars(
    logger: WrappedLogger, method: str, event_dict: EventDict
) -> EventDict:
    """Inject per-request context variables into every log record."""
    event_dict.setdefault("request_id", _request_id_var.get())
    event_dict.setdefault("user_id", _user_id_var.get())
    event_dict.setdefault("correlation_id", _correlation_id_var.get())
    return event_dict


def _rename_event_key(
    logger: WrappedLogger, method: str, event_dict: EventDict
) -> EventDict:
    """Rename 'event' to 'message' for readability in JSON output."""
    event_dict["message"] = event_dict.pop("event", "")
    return event_dict


# ---------------------------------------------------------------------------
# Standard-library logging bridge (RequestIDFilter)
# ---------------------------------------------------------------------------


class RequestIDFilter(logging.Filter):
    """Inject request_id / correlation_id into stdlib log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id_var.get()  # type: ignore[attr-defined]
        record.correlation_id = _correlation_id_var.get()  # type: ignore[attr-defined]
        return True


# ---------------------------------------------------------------------------
# Main configuration entry point
# ---------------------------------------------------------------------------


def configure_logging(log_level: str = "INFO", log_file: str = "logs/sentinelmesh.log") -> None:
    """Configure structlog and the standard-library root logger.

    * Development: colored, human-readable console output.
    * Production: JSON structured output, rotated log file.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    # ---- ensure log directory exists ----
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # ---- shared processors ----
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.CallsiteParameterAdder(
            parameters=[
                structlog.processors.CallsiteParameter.FILENAME,
                structlog.processors.CallsiteParameter.LINENO,
                structlog.processors.CallsiteParameter.FUNC_NAME,
            ]
        ),
        _inject_context_vars,
        structlog.processors.StackInfoRenderer(),
    ]

    # ---- stdlib root logger ----
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.addFilter(RequestIDFilter())

    # Rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        filename=str(log_path),
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.addFilter(RequestIDFilter())

    # Detect environment for renderer selection
    env = os.getenv("ENVIRONMENT", "development").lower()
    is_production = env in ("production", "staging", "prod")

    if is_production:
        # JSON renderer for production / staging
        formatter = logging.Formatter(
            '{"ts":"%(asctime)s","level":"%(levelname)s","name":"%(name)s",'
            '"request_id":"%(request_id)s","correlation_id":"%(correlation_id)s",'
            '"message":"%(message)s"}'
        )
        renderer: Any = structlog.processors.JSONRenderer()
    else:
        # Colored console renderer for development
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s (req=%(request_id)s): %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    # Silence noisy third-party loggers
    for noisy in ("sqlalchemy.engine", "uvicorn.access", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Wire structlog into stdlib so both use the same pipeline
    structlog.stdlib.ProcessorFormatter.wrap_for_formatter  # noqa: B018

    _stdlib_formatter = structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )
    for handler in (console_handler, file_handler):
        handler.setFormatter(_stdlib_formatter)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a structlog bound logger for the given name."""
    return structlog.get_logger(name)


# ---------------------------------------------------------------------------
# Performance logging decorator
# ---------------------------------------------------------------------------


def log_performance(func: Callable | None = None, *, logger_name: str | None = None) -> Any:
    """Decorator that logs function name, execution duration, and success/failure."""

    def decorator(fn: Callable) -> Callable:
        _logger = get_logger(logger_name or fn.__module__)

        if _is_coroutine(fn):
            @wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                start = time.perf_counter()
                try:
                    result = await fn(*args, **kwargs)
                    duration_ms = (time.perf_counter() - start) * 1000
                    _logger.info(
                        "function completed",
                        function=fn.__qualname__,
                        duration_ms=round(duration_ms, 3),
                        success=True,
                    )
                    return result
                except Exception as exc:
                    duration_ms = (time.perf_counter() - start) * 1000
                    _logger.error(
                        "function failed",
                        function=fn.__qualname__,
                        duration_ms=round(duration_ms, 3),
                        success=False,
                        error=str(exc),
                    )
                    raise

            return async_wrapper
        else:
            @wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                start = time.perf_counter()
                try:
                    result = fn(*args, **kwargs)
                    duration_ms = (time.perf_counter() - start) * 1000
                    _logger.info(
                        "function completed",
                        function=fn.__qualname__,
                        duration_ms=round(duration_ms, 3),
                        success=True,
                    )
                    return result
                except Exception as exc:
                    duration_ms = (time.perf_counter() - start) * 1000
                    _logger.error(
                        "function failed",
                        function=fn.__qualname__,
                        duration_ms=round(duration_ms, 3),
                        success=False,
                        error=str(exc),
                    )
                    raise

            return sync_wrapper

    if func is not None:
        return decorator(func)
    return decorator


def _is_coroutine(fn: Callable) -> bool:
    import asyncio
    return asyncio.iscoroutinefunction(fn)
