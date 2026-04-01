"""Logs listing routes."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db_session
from models.log_models import Log
from models.schemas import LogRead

router = APIRouter(prefix="/logs", tags=["Logs"])


@router.get("", response_model=dict)
async def list_logs(
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    query = select(Log)
    if severity:
        query = query.where(Log.severity == severity)
    if source:
        query = query.where(Log.source == source)
    if start_time:
        query = query.where(Log.timestamp >= start_time)
    if end_time:
        query = query.where(Log.timestamp <= end_time)

    query = query.order_by(desc(Log.timestamp)).offset((page - 1) * size).limit(size)
    rows = (await db.execute(query)).scalars().all()
    return {"items": [LogRead.model_validate(r).model_dump() for r in rows], "count": len(rows)}

