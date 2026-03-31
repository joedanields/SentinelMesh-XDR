"""Ingestion pipeline orchestrator – manages ingesters, workers, DLQ, and metrics."""
from __future__ import annotations

import asyncio
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

import structlog

from .base_ingester import AbstractIngester

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Throughput / latency sliding window
# ---------------------------------------------------------------------------


@dataclass
class _WindowMetrics:
    """Track events-per-second and latency over a sliding time window."""

    window_seconds: int = 60
    _events: deque = field(default_factory=lambda: deque())
    _latencies: deque = field(default_factory=lambda: deque())

    def record(self, count: int, latency_ms: float) -> None:
        now = time.monotonic()
        self._events.append((now, count))
        self._latencies.append((now, latency_ms))
        self._purge(now)

    def _purge(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()
        while self._latencies and self._latencies[0][0] < cutoff:
            self._latencies.popleft()

    @property
    def throughput_eps(self) -> float:
        """Events per second over the window."""
        if not self._events:
            return 0.0
        total = sum(c for _, c in self._events)
        return total / self.window_seconds

    @property
    def avg_latency_ms(self) -> float:
        if not self._latencies:
            return 0.0
        return sum(l for _, l in self._latencies) / len(self._latencies)

    @property
    def p95_latency_ms(self) -> float:
        if not self._latencies:
            return 0.0
        sorted_l = sorted(l for _, l in self._latencies)
        idx = int(len(sorted_l) * 0.95)
        return sorted_l[min(idx, len(sorted_l) - 1)]


# ---------------------------------------------------------------------------
# Pipeline metrics
# ---------------------------------------------------------------------------


@dataclass
class PipelineMetrics:
    total_processed: int = 0
    total_failed: int = 0
    total_dlq: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    window: _WindowMetrics = field(default_factory=_WindowMetrics)

    def to_dict(self) -> dict[str, Any]:
        uptime = (datetime.now(timezone.utc) - self.started_at).total_seconds()
        return {
            "total_processed": self.total_processed,
            "total_failed": self.total_failed,
            "total_dlq": self.total_dlq,
            "throughput_eps": round(self.window.throughput_eps, 2),
            "avg_latency_ms": round(self.window.avg_latency_ms, 2),
            "p95_latency_ms": round(self.window.p95_latency_ms, 2),
            "uptime_seconds": round(uptime, 1),
            "started_at": self.started_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# Dead-letter queue entry
# ---------------------------------------------------------------------------


@dataclass
class DLQEntry:
    record: dict[str, Any]
    ingester_name: str
    error: str
    attempts: int
    failed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    dlq_id: str = field(default_factory=lambda: str(uuid.uuid4()))


# ---------------------------------------------------------------------------
# IngestionPipeline
# ---------------------------------------------------------------------------


class IngestionPipeline:
    """Orchestrate multiple :class:`AbstractIngester` instances through a
    shared asyncio queue and configurable worker pool.

    Architecture
    ------------
    ::

        [Ingester A] ──┐
        [Ingester B] ──┼──> [main_queue] ──> [Worker 1..N] ──> [on_event callback]
        [Ingester C] ──┘                                    └──> [DLQ on failure]

    Features
    --------
    * Queue-based decoupling between producers (ingesters) and consumers (workers).
    * Per-ingester polling tasks.
    * ``on_event`` async callback – wire in the detection engine here.
    * Dead-letter queue (in-memory deque, bounded to ``dlq_maxsize``).
    * Sliding-window throughput / latency metrics.
    * ``health()`` endpoint for liveness probes.
    """

    def __init__(
        self,
        workers: int = 4,
        queue_maxsize: int = 100_000,
        dlq_maxsize: int = 10_000,
        on_event: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> None:
        self.workers = max(1, workers)
        self.on_event = on_event
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_maxsize)
        self._dlq: deque[DLQEntry] = deque(maxlen=dlq_maxsize)
        self._ingesters: dict[str, AbstractIngester] = {}
        self._poller_tasks: dict[str, asyncio.Task] = {}
        self._worker_tasks: list[asyncio.Task] = []
        self._running = False
        self._metrics = PipelineMetrics()
        self._log = logger.bind(component="IngestionPipeline")

    # ------------------------------------------------------------------
    # Ingester registration
    # ------------------------------------------------------------------

    def register(self, ingester: AbstractIngester) -> None:
        """Register an ingester with the pipeline."""
        self._ingesters[ingester.source_name] = ingester
        self._log.info("ingester registered", source=ingester.source_name)

    def unregister(self, source_name: str) -> None:
        self._ingesters.pop(source_name, None)
        task = self._poller_tasks.pop(source_name, None)
        if task:
            task.cancel()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start all ingesters, polling tasks, and worker tasks."""
        if self._running:
            return
        self._running = True
        self._metrics = PipelineMetrics()
        self._log.info("pipeline starting", workers=self.workers, ingesters=list(self._ingesters))

        # Start all registered ingesters
        for ingester in self._ingesters.values():
            await ingester.start()
            task = asyncio.create_task(
                self._poll_ingester(ingester),
                name=f"poller_{ingester.source_name}",
            )
            self._poller_tasks[ingester.source_name] = task

        # Spawn worker pool
        self._worker_tasks = [
            asyncio.create_task(self._worker(worker_id=i), name=f"pipeline_worker_{i}")
            for i in range(self.workers)
        ]
        self._log.info("pipeline started")

    async def stop(self) -> None:
        """Gracefully drain and stop the pipeline."""
        if not self._running:
            return
        self._running = False
        self._log.info("pipeline stopping")

        # Stop ingesters
        for ingester in self._ingesters.values():
            await ingester.stop()

        # Cancel poller tasks
        for task in self._poller_tasks.values():
            task.cancel()
        await asyncio.gather(*self._poller_tasks.values(), return_exceptions=True)
        self._poller_tasks.clear()

        # Drain queue with a deadline
        try:
            await asyncio.wait_for(self._queue.join(), timeout=10.0)
        except asyncio.TimeoutError:
            self._log.warning("queue drain timed out", remaining=self._queue.qsize())

        # Cancel workers
        for task in self._worker_tasks:
            task.cancel()
        await asyncio.gather(*self._worker_tasks, return_exceptions=True)
        self._worker_tasks.clear()

        self._log.info("pipeline stopped", metrics=self._metrics.to_dict())

    # ------------------------------------------------------------------
    # Internal tasks
    # ------------------------------------------------------------------

    async def _poll_ingester(self, ingester: AbstractIngester) -> None:
        """Continuously call ``ingest_with_retry`` and push events to the queue."""
        log = self._log.bind(ingester=ingester.source_name)
        while self._running:
            try:
                batch = await ingester.ingest_with_retry()
                if batch:
                    valid, failed = await ingester.process_batch(batch)
                    for rec in valid:
                        if not self._queue.full():
                            await self._queue.put(rec)
                        else:
                            log.warning("main queue full – event dropped")
                            self._metrics.total_failed += 1
                    for rec in failed:
                        self._add_to_dlq(rec, ingester.source_name, "batch_process_failure")
                else:
                    await asyncio.sleep(0.1)  # brief back-off when idle
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("poller error", error=str(exc))
                await asyncio.sleep(1.0)

    async def _worker(self, worker_id: int) -> None:
        """Consume events from the queue and invoke the on_event callback."""
        log = self._log.bind(worker_id=worker_id)
        while self._running or not self._queue.empty():
            try:
                record = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                t_start = time.perf_counter()
                try:
                    if self.on_event:
                        await self.on_event(record)
                    self._metrics.total_processed += 1
                    latency_ms = (time.perf_counter() - t_start) * 1000
                    self._metrics.window.record(1, latency_ms)
                except Exception as exc:
                    log.error("on_event callback failed", error=str(exc))
                    self._add_to_dlq(record, "worker", str(exc))
                    self._metrics.total_failed += 1
                finally:
                    self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    def _add_to_dlq(self, record: dict[str, Any], ingester_name: str, error: str, attempts: int = 1) -> None:
        entry = DLQEntry(record=record, ingester_name=ingester_name, error=error, attempts=attempts)
        self._dlq.append(entry)
        self._metrics.total_dlq += 1
        self._log.debug("event added to DLQ", error=error, dlq_size=len(self._dlq))

    # ------------------------------------------------------------------
    # Queue ingestion (for external callers bypassing ingesters)
    # ------------------------------------------------------------------

    async def put(self, record: dict[str, Any]) -> bool:
        """Directly enqueue a pre-normalised record.  Returns False if queue is full."""
        if self._queue.full():
            return False
        await self._queue.put(record)
        return True

    # ------------------------------------------------------------------
    # DLQ management
    # ------------------------------------------------------------------

    def dlq_snapshot(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the most recent DLQ entries as dicts."""
        entries = list(self._dlq)[-limit:]
        return [
            {
                "dlq_id": e.dlq_id,
                "ingester": e.ingester_name,
                "error": e.error,
                "attempts": e.attempts,
                "failed_at": e.failed_at,
                "record_preview": str(e.record)[:200],
            }
            for e in entries
        ]

    async def replay_dlq(self, limit: int = 100) -> int:
        """Attempt to re-process up to *limit* DLQ entries.  Returns count re-queued."""
        replayed = 0
        to_replay = list(self._dlq)[:limit]
        for entry in to_replay:
            if not self._queue.full():
                await self._queue.put(entry.record)
                self._dlq.remove(entry)
                replayed += 1
        self._log.info("DLQ replay complete", replayed=replayed)
        return replayed

    # ------------------------------------------------------------------
    # Health / metrics
    # ------------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        ingester_health = {
            name: ing.health()
            for name, ing in self._ingesters.items()
        }
        return {
            "status": "running" if self._running else "stopped",
            "queue_size": self._queue.qsize(),
            "dlq_size": len(self._dlq),
            "workers": self.workers,
            "metrics": self._metrics.to_dict(),
            "ingesters": ingester_health,
        }

    def metrics(self) -> dict[str, Any]:
        return self._metrics.to_dict()

    def __repr__(self) -> str:
        return (
            f"<IngestionPipeline running={self._running} "
            f"workers={self.workers} ingesters={list(self._ingesters)}>"
        )
