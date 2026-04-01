"""Event correlation routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from api.deps import get_attack_chain_detector, get_correlation_engine
from correlation.attack_chain_detector import AttackChainDetector
from correlation.correlation_engine import CorrelationEngine

router = APIRouter(prefix="/correlation", tags=["Correlation"])


@router.post("")
async def correlate_events(
    payload: dict[str, Any],
    engine: CorrelationEngine = Depends(get_correlation_engine),
    chain_detector: AttackChainDetector = Depends(get_attack_chain_detector),
) -> dict[str, Any]:
    events = payload.get("events")
    if not isinstance(events, list) or not events:
        raise HTTPException(status_code=400, detail="events must be a non-empty list")

    correlated = engine.correlate(events)
    chain_matches = chain_detector.detect(events)
    return {
        "events_processed": len(events),
        "correlated_events": [c.to_dict() for c in correlated],
        "attack_chain_matches": [m.to_dict() for m in chain_matches],
    }


@router.post("/windows")
async def correlate_events_multi_window(
    payload: dict[str, Any],
    engine: CorrelationEngine = Depends(get_correlation_engine),
) -> dict[str, Any]:
    events = payload.get("events")
    if not isinstance(events, list) or not events:
        raise HTTPException(status_code=400, detail="events must be a non-empty list")

    results = engine.correlate_with_windows(events)
    return {
        "events_processed": len(events),
        "windows": {
            k: [item.to_dict() for item in v]
            for k, v in results.items()
        },
    }
