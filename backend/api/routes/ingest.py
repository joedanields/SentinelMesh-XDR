"""Ingestion API routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db_session
from models.log_models import Log
from models.schemas import LogCreate, LogRead
from utils.logging_config import get_logger

router = APIRouter(prefix="/ingest", tags=["Ingestion"])
logger = get_logger(__name__)


@router.post("", response_model=LogRead)
async def ingest_log(payload: LogCreate, db: AsyncSession = Depends(get_db_session)) -> Log:
    """Accept and persist a single normalized log."""
    try:
        log = Log(
            timestamp=payload.timestamp,
            source=payload.source,
            source_type=payload.source_type,
            raw_log=payload.raw_log,
            severity=payload.severity,
            tags=payload.tags,
            host=payload.host,
            ip_address=payload.ip_address,
            user_id=payload.user_id,
            process_name=payload.process_name,
            event_type=payload.event_type,
            parsed_fields=payload.parsed_fields,
            normalized_log=payload.parsed_fields or {},
            is_processed=False,
        )
        db.add(log)
        await db.flush()
        await db.refresh(log)
        logger.info("Log ingested", log_id=log.id, source=log.source, severity=log.severity.value)
        return log
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed ingesting log", error=str(exc))
        raise HTTPException(status_code=400, detail=f"Failed to ingest log: {exc}") from exc

