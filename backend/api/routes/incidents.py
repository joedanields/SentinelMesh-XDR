"""Incident lifecycle routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.deps import get_incident_manager
from incident_response.incident_manager import IncidentManager

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("")
async def list_incidents(status: str | None = None, manager: IncidentManager = Depends(get_incident_manager)) -> dict:
    incidents = manager.list_incidents(status=status)
    return {"items": [i.to_dict() for i in incidents], "count": len(incidents)}


@router.post("")
async def create_incident(payload: dict, manager: IncidentManager = Depends(get_incident_manager)) -> dict:
    alerts = payload.get("alerts", [])
    if not isinstance(alerts, list):
        raise HTTPException(status_code=400, detail="alerts must be a list")
    incident = manager.create_incident(
        alerts=alerts,
        title=payload.get("title"),
        description=payload.get("description"),
    )
    return incident.to_dict()


@router.patch("/{incident_id}/status")
async def update_incident_status(
    incident_id: str,
    payload: dict,
    manager: IncidentManager = Depends(get_incident_manager),
) -> dict:
    status = payload.get("status")
    if not status:
        raise HTTPException(status_code=400, detail="status is required")
    try:
        incident = manager.update_incident_status(incident_id=incident_id, status=status, actor="api")
        return incident.to_dict()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

