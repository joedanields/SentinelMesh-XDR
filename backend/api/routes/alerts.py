"""Alert API routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.deps import get_alert_manager
from incident_response.alert_manager import AlertManager

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("")
async def list_alerts(
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    manager: AlertManager = Depends(get_alert_manager),
) -> dict:
    alerts = manager.list_alerts(status=status, severity=severity, limit=500)
    return {"items": [a.to_dict() for a in alerts], "count": len(alerts)}

