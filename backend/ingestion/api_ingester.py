"""API-based log ingester – HTTP POST, Syslog UDP, and webhook reception."""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import structlog

from .base_ingester import AbstractIngester, RetryConfig
from .normalizer import LogNormalizer

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class _RateLimiter:
    """Token-bucket rate limiter per source key."""

    def __init__(self, max_rps: float = 1000.0) -> None:
        self.max_rps = max_rps
        self._buckets: dict[str, tuple[float, float]] = {}   # key -> (tokens, last_refill)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.get(key, (self.max_rps, now))
        elapsed = now - last
        tokens = min(self.max_rps, tokens + elapsed * self.max_rps)
        if tokens >= 1.0:
            self._buckets[key] = (tokens - 1.0, now)
            return True
        self._buckets[key] = (tokens, now)
        return False

    def reset(self, key: str) -> None:
        self._buckets.pop(key, None)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _validate_log_dict(d: Any) -> bool:
    if not isinstance(d, dict):
        return False
    # Must have at least one meaningful field
    meaningful = {"message", "msg", "log", "raw", "data", "text", "event"}
    return bool(meaningful.intersection(d.keys())) or len(d) >= 2


def _sanitise_batch(raw_batch: Any) -> list[dict[str, Any]]:
    if isinstance(raw_batch, list):
        return [r for r in raw_batch if isinstance(r, dict)]
    if isinstance(raw_batch, dict):
        return [raw_batch]
    return []


# ---------------------------------------------------------------------------
# APIIngester
# ---------------------------------------------------------------------------


class APIIngester(AbstractIngester):
    """Accept logs from HTTP POST endpoints, syslog UDP, and webhooks.

    Design
    ------
    * **HTTP handler** – call :meth:`handle_http_batch` from your FastAPI
      route; it validates, rate-limits, queues, and returns a receipt dict.
    * **UDP syslog** – start via :meth:`start_syslog_udp`; binds to the
      given host/port and drains packets into the internal queue.
    * **Webhook** – :meth:`handle_webhook` accepts a generic payload dict
      and normalises it similarly to the HTTP batch handler.
    * **ingest()** – drain the queue in batches for the pipeline worker.
    """

    def __init__(
        self,
        source_name: str = "api_ingester",
        batch_size: int = 500,
        max_rps_per_source: float = 500.0,
        syslog_host: str = "0.0.0.0",
        syslog_port: int = 5140,
        retry_config: RetryConfig | None = None,
    ) -> None:
        super().__init__(
            source_name=source_name,
            source_type="api",
            batch_size=batch_size,
            retry_config=retry_config,
        )
        self.syslog_host = syslog_host
        self.syslog_port = syslog_port
        self._rate_limiter = _RateLimiter(max_rps=max_rps_per_source)
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100_000)
        self._normalizer = LogNormalizer(default_source=source_name, default_source_type="api")
        self._syslog_transport: asyncio.BaseTransport | None = None
        self._log = logger.bind(ingester="APIIngester", source=source_name)
        # Per-source counters for observability
        self._source_counts: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------
    # AbstractIngester interface
    # ------------------------------------------------------------------

    async def ingest(self) -> list[dict[str, Any]]:
        """Drain up to *batch_size* items from the internal queue."""
        batch: list[dict[str, Any]] = []
        deadline = asyncio.get_event_loop().time() + 0.5
        while len(batch) < self.batch_size:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=remaining)
                batch.append(item)
            except asyncio.TimeoutError:
                break
        return batch

    def validate(self, raw: dict[str, Any]) -> bool:
        return _validate_log_dict(raw)

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        source = raw.pop("_source_hint", self.source_name)
        source_type = raw.pop("_source_type_hint", "api")
        nlog = self._normalizer.normalize(raw, source=source, source_type=source_type)
        return nlog.to_dict()

    # ------------------------------------------------------------------
    # HTTP batch handler (called by FastAPI route)
    # ------------------------------------------------------------------

    async def handle_http_batch(
        self,
        payload: list[dict[str, Any]] | dict[str, Any],
        source_id: str = "http",
        source_type: str = "api",
    ) -> dict[str, Any]:
        """Validate, rate-limit, and enqueue a batch from an HTTP POST.

        Returns a receipt dict suitable for returning as a JSON response.
        """
        if not self._rate_limiter.allow(source_id):
            self._log.warning("rate limit exceeded", source_id=source_id)
            return {
                "status": "rate_limited",
                "message": "Too many requests from this source",
                "accepted": 0,
            }

        records = _sanitise_batch(payload)
        if not records:
            return {"status": "error", "message": "Empty or invalid payload", "accepted": 0}

        # Cap batch size
        records = records[: self.batch_size]
        accepted = 0
        rejected = 0

        for rec in records:
            if not _validate_log_dict(rec):
                rejected += 1
                continue
            rec["_source_hint"] = source_id
            rec["_source_type_hint"] = source_type
            rec.setdefault("_ingested_at", datetime.now(timezone.utc).isoformat())
            rec.setdefault("_request_id", str(uuid.uuid4()))

            if not self._queue.full():
                await self._queue.put(rec)
                accepted += 1
                self._source_counts[source_id] += 1
                self.metrics.record_ingested()
            else:
                rejected += 1
                self.metrics.record_error("queue full")

        self._log.info(
            "http batch received",
            source_id=source_id,
            accepted=accepted,
            rejected=rejected,
        )
        return {
            "status": "ok",
            "accepted": accepted,
            "rejected": rejected,
            "request_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Webhook handler
    # ------------------------------------------------------------------

    async def handle_webhook(
        self,
        payload: dict[str, Any],
        source_id: str = "webhook",
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Accept a webhook POST payload and enqueue it for processing."""
        if not self._rate_limiter.allow(f"webhook:{source_id}"):
            return {"status": "rate_limited", "accepted": 0}

        if not isinstance(payload, dict):
            return {"status": "error", "message": "Payload must be a JSON object"}

        # Flatten nested 'events' / 'logs' keys (common webhook conventions)
        records: list[dict[str, Any]] = []
        for key in ("events", "logs", "records", "data", "alerts"):
            if key in payload and isinstance(payload[key], list):
                records.extend(r for r in payload[key] if isinstance(r, dict))
                break
        if not records:
            records = [payload]

        accepted = 0
        for rec in records[: self.batch_size]:
            rec["_source_hint"] = source_id
            rec["_source_type_hint"] = "webhook"
            if headers:
                _SENSITIVE_HEADERS = frozenset({
                    "authorization", "x-api-key", "x-auth-token", "cookie",
                    "set-cookie", "token", "x-token", "api-key", "secret",
                    "x-secret", "x-access-token", "x-session-token",
                })
                rec["_webhook_headers"] = {
                    k: v for k, v in headers.items()
                    if k.lower() not in _SENSITIVE_HEADERS
                    and not any(s in k.lower() for s in ("token", "secret", "key", "auth", "password"))
                }
            if not self._queue.full():
                await self._queue.put(rec)
                accepted += 1
                self.metrics.record_ingested()

        return {"status": "ok", "accepted": accepted}

    # ------------------------------------------------------------------
    # UDP syslog listener
    # ------------------------------------------------------------------

    async def start_syslog_udp(self) -> None:
        """Bind a UDP socket and receive syslog datagrams asynchronously."""
        loop = asyncio.get_event_loop()

        class _SyslogProtocol(asyncio.DatagramProtocol):
            def __init__(self_, ingester: "APIIngester") -> None:
                self_._ingester = ingester

            def datagram_received(self_, data: bytes, addr: tuple) -> None:
                try:
                    raw_str = data.decode("utf-8", errors="replace").strip()
                    rec: dict[str, Any] = {
                        "raw_log": raw_str,
                        "message": raw_str,
                        "_source_hint": f"syslog:{addr[0]}",
                        "_source_type_hint": "syslog",
                        "ip_address": addr[0],
                    }
                    if not self_._ingester._queue.full():
                        loop.call_soon_threadsafe(self_._ingester._queue.put_nowait, rec)
                        self_._ingester.metrics.record_ingested()
                except Exception as exc:
                    self_._ingester._log.warning("syslog datagram error", error=str(exc))

            def error_received(self_, exc: Exception) -> None:
                self_._ingester._log.error("syslog UDP error", error=str(exc))

        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _SyslogProtocol(self),
                local_addr=(self.syslog_host, self.syslog_port),
            )
            self._syslog_transport = transport
            self._log.info("syslog UDP listener started", host=self.syslog_host, port=self.syslog_port)
        except OSError as exc:
            self._log.error("failed to bind syslog UDP", error=str(exc))

    async def stop(self) -> None:
        if self._syslog_transport:
            self._syslog_transport.close()
        await super().stop()

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def source_stats(self) -> dict[str, Any]:
        return {
            "queue_size": self._queue.qsize(),
            "source_counts": dict(self._source_counts),
            "metrics": self.metrics.to_dict(),
        }
