"""Ingestion API routes."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db_session
from ingestion.normalizer import LogNormalizer
from ingestion.stream_ingester import EventGenerator
from models.log_models import Log, LogSeverity, SourceType
from models.schemas import LogRead
from utils.logging_config import get_logger

router = APIRouter(prefix="/ingest", tags=["Ingestion"])
logger = get_logger(__name__)

_normalizer = LogNormalizer(default_source="api_ingest", default_source_type="api")


class IngestRequest(BaseModel):
    data: Any
    format: Literal["auto", "json", "csv", "raw"] = "auto"
    source: str = "api_ingest"
    source_type: str = "custom"


class BatchIngestRequest(BaseModel):
    records: list[IngestRequest] = Field(default_factory=list, min_length=1, max_length=5000)


class RealtimeSimulateRequest(BaseModel):
    events_per_second: int = Field(default=5, ge=1, le=100)
    duration_seconds: int = Field(default=10, ge=1, le=300)


def _to_source_type(value: str | None) -> SourceType:
    val = (value or "").lower().strip()
    try:
        return SourceType(val)
    except ValueError:
        return SourceType.custom


def _to_severity(value: str | None) -> LogSeverity:
    val = (value or "info").lower().strip()
    try:
        return LogSeverity(val)
    except ValueError:
        if val in {"medium", "low", "notice", "debug"}:
            return LogSeverity.info
        return LogSeverity.warning if val == "warn" else LogSeverity.info


def _to_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _persist_log(db: AsyncSession, normalized: dict[str, Any]) -> Log:
    log = Log(
        timestamp=_to_datetime(normalized.get("timestamp")),
        source=str(normalized.get("source") or "api_ingest"),
        source_type=_to_source_type(str(normalized.get("source_type") or "custom")),
        raw_log=str(normalized.get("raw_log") or normalized.get("message") or ""),
        normalized_log=normalized,
        severity=_to_severity(str(normalized.get("severity") or "info")),
        tags=list(normalized.get("tags") or []),
        host=normalized.get("host"),
        ip_address=normalized.get("ip_address"),
        user_id=normalized.get("user") or normalized.get("user_id"),
        process_name=normalized.get("process") or normalized.get("process_name"),
        event_type=normalized.get("event_type"),
        parsed_fields=normalized.get("parsed_fields") or {},
        is_processed=False,
    )
    db.add(log)
    return log


def _normalize_payload(record: IngestRequest) -> list[dict[str, Any]]:
    src = record.source
    stype = record.source_type

    if record.format == "json":
        if isinstance(record.data, list):
            return [_normalizer.normalize(item, source=src, source_type=stype).to_dict() for item in record.data]
        if not isinstance(record.data, dict):
            raise ValueError("JSON format requires object or array input")
        return [_normalizer.normalize(record.data, source=src, source_type=stype).to_dict()]

    if record.format == "csv":
        if not isinstance(record.data, str):
            raise ValueError("CSV format requires string input")
        rows = [r for r in csv.reader(io.StringIO(record.data)) if r]
        return [
            _normalizer.normalize(",".join(row), source=src, source_type=stype).to_dict()
            for row in rows
        ]

    if record.format == "raw":
        if not isinstance(record.data, str):
            raise ValueError("RAW format requires string input")
        lines = [line for line in record.data.splitlines() if line.strip()]
        return [_normalizer.normalize(line, source=src, source_type=stype).to_dict() for line in lines]

    # auto
    if isinstance(record.data, list):
        return [_normalizer.normalize(item, source=src, source_type=stype).to_dict() for item in record.data]
    return [_normalizer.normalize(record.data, source=src, source_type=stype).to_dict()]


@router.post("", response_model=LogRead)
async def ingest_log(payload: IngestRequest, db: AsyncSession = Depends(get_db_session)) -> Log:
    """Accept, normalize, and persist a single log payload."""
    try:
        normalized = _normalize_payload(payload)
        if not normalized:
            raise HTTPException(status_code=400, detail="No log records found to ingest")
        log = _persist_log(db, normalized[0])
        await db.flush()
        await db.refresh(log)
        logger.info("Log ingested", log_id=log.id, source=log.source, severity=log.severity.value)
        return log
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed ingesting log", error=str(exc))
        raise HTTPException(status_code=400, detail="Failed to ingest log payload") from exc


@router.post("/batch")
async def ingest_logs_batch(payload: BatchIngestRequest, db: AsyncSession = Depends(get_db_session)) -> dict[str, Any]:
    """Ingest a batch of logs with per-record malformed-data handling."""
    accepted: list[str] = []
    rejected: list[dict[str, Any]] = []

    for index, record in enumerate(payload.records):
        try:
            normalized_records = _normalize_payload(record)
            if not normalized_records:
                raise ValueError("empty normalized output")
            for n in normalized_records:
                row = _persist_log(db, n)
                await db.flush()
                accepted.append(row.id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("batch ingest record rejected", index=index, error_type=type(exc).__name__)
            rejected.append({"index": index, "error": "malformed_record", "error_type": type(exc).__name__})

    return {
        "accepted": len(accepted),
        "rejected": len(rejected),
        "accepted_ids": accepted,
        "errors": rejected,
    }


@router.post("/simulate-realtime")
async def ingest_realtime_simulation(
    payload: RealtimeSimulateRequest,
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Simulate real-time ingestion by generating synthetic streaming events."""
    total = payload.events_per_second * payload.duration_seconds
    generated = []
    for _ in range(total):
        # weighted random event generator used by stream ingestion
        event = EventGenerator.http_request()
        event.setdefault("raw_log", str(event))
        row = _persist_log(db, event)
        await db.flush()
        generated.append(row.id)

    logger.info("Realtime simulation ingested", count=len(generated))
    return {
        "generated": len(generated),
        "events_per_second": payload.events_per_second,
        "duration_seconds": payload.duration_seconds,
        "log_ids": generated,
    }
