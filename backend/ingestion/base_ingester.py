"""Abstract base class for all SentinelMesh XDR log ingesters."""
from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Metrics container
# ---------------------------------------------------------------------------


@dataclass
class IngesterMetrics:
    total_ingested: int = 0
    total_errors: int = 0
    total_batches: int = 0
    last_ingest_time: datetime | None = None
    last_error_time: datetime | None = None
    last_error_message: str = ""
    bytes_processed: int = 0

    @property
    def error_rate(self) -> float:
        total = self.total_ingested + self.total_errors
        return self.total_errors / total if total else 0.0

    def record_ingested(self, count: int = 1, bytes_count: int = 0) -> None:
        self.total_ingested += count
        self.bytes_processed += bytes_count
        self.last_ingest_time = datetime.now(timezone.utc)

    def record_error(self, message: str) -> None:
        self.total_errors += 1
        self.last_error_time = datetime.now(timezone.utc)
        self.last_error_message = message

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_ingested": self.total_ingested,
            "total_errors": self.total_errors,
            "total_batches": self.total_batches,
            "error_rate": round(self.error_rate, 4),
            "last_ingest_time": self.last_ingest_time.isoformat() if self.last_ingest_time else None,
            "last_error_time": self.last_error_time.isoformat() if self.last_error_time else None,
            "last_error_message": self.last_error_message,
            "bytes_processed": self.bytes_processed,
        }


# ---------------------------------------------------------------------------
# Retry configuration
# ---------------------------------------------------------------------------


@dataclass
class RetryConfig:
    max_attempts: int = 3
    base_delay: float = 1.0          # seconds
    max_delay: float = 60.0          # seconds
    exponential_base: float = 2.0
    jitter: bool = True


# ---------------------------------------------------------------------------
# Abstract base ingester
# ---------------------------------------------------------------------------


class AbstractIngester(ABC):
    """Abstract base class for all log ingesters.

    Concrete sub-classes must implement :meth:`ingest`, :meth:`validate`,
    and :meth:`normalize`.  Common retry logic, metrics tracking, and
    structured logging are provided here so sub-classes stay lean.
    """

    def __init__(
        self,
        source_name: str,
        source_type: str,
        batch_size: int = 500,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.source_name = source_name
        self.source_type = source_type
        self.batch_size = batch_size
        self.retry_config = retry_config or RetryConfig()
        self.metrics = IngesterMetrics()
        self._running = False
        self._log = logger.bind(
            ingester=self.__class__.__name__,
            source=source_name,
            source_type=source_type,
        )

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def ingest(self) -> list[dict[str, Any]]:
        """Fetch/read the next batch of raw log records.

        Returns a list of raw record dicts (un-normalised).
        """

    @abstractmethod
    def validate(self, raw: dict[str, Any]) -> bool:
        """Return True if *raw* is structurally valid for this source."""

    @abstractmethod
    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Convert *raw* record to the unified SentinelMesh log schema."""

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Mark the ingester as running."""
        self._running = True
        self._log.info("ingester started")

    async def stop(self) -> None:
        """Signal the ingester to stop gracefully."""
        self._running = False
        self._log.info("ingester stopped", metrics=self.metrics.to_dict())

    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Retry helper
    # ------------------------------------------------------------------

    async def ingest_with_retry(self) -> list[dict[str, Any]]:
        """Call :meth:`ingest` with exponential-backoff retry.

        Returns the batch on success, or an empty list after exhausting all
        retry attempts.
        """
        cfg = self.retry_config
        attempt = 0
        last_exc: Exception | None = None

        while attempt < cfg.max_attempts:
            try:
                batch = await self.ingest()
                if attempt > 0:
                    self._log.info("ingest succeeded after retry", attempt=attempt)
                return batch
            except Exception as exc:
                attempt += 1
                last_exc = exc
                delay = min(
                    cfg.base_delay * (cfg.exponential_base ** (attempt - 1)),
                    cfg.max_delay,
                )
                if cfg.jitter:
                    import random
                    delay *= 0.5 + random.random() * 0.5

                self.metrics.record_error(str(exc))
                self._log.warning(
                    "ingest error – will retry",
                    attempt=attempt,
                    max_attempts=cfg.max_attempts,
                    delay_s=round(delay, 2),
                    error=str(exc),
                )
                if attempt < cfg.max_attempts:
                    await asyncio.sleep(delay)

        self._log.error(
            "ingest failed – exhausted retries",
            max_attempts=cfg.max_attempts,
            last_error=str(last_exc),
        )
        return []

    # ------------------------------------------------------------------
    # Batch processing helper
    # ------------------------------------------------------------------

    async def process_batch(
        self,
        raw_records: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Validate + normalise a batch of raw records.

        Returns ``(valid_normalised, failed_raw)`` tuple.
        """
        valid: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []
        batch_start = time.perf_counter()

        for raw in raw_records:
            try:
                if not self.validate(raw):
                    self._log.debug("record failed validation", raw=str(raw)[:120])
                    failed.append(raw)
                    self.metrics.record_error("validation failed")
                    continue

                normalised = self.normalize(raw)
                valid.append(normalised)
                raw_size = len(str(raw).encode())
                self.metrics.record_ingested(bytes_count=raw_size)
            except Exception as exc:
                self._log.warning("normalisation error", error=str(exc), raw=str(raw)[:120])
                self.metrics.record_error(str(exc))
                failed.append(raw)

        self.metrics.total_batches += 1
        elapsed_ms = (time.perf_counter() - batch_start) * 1000
        self._log.debug(
            "batch processed",
            valid=len(valid),
            failed=len(failed),
            elapsed_ms=round(elapsed_ms, 1),
        )
        return valid, failed

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "source_type": self.source_type,
            "running": self._running,
            "metrics": self.metrics.to_dict(),
        }
