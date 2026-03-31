"""Simulation routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.deps import get_simulation_engine
from simulation.simulation_engine import SimulationEngine

router = APIRouter(prefix="/simulate", tags=["Simulation"])


@router.get("/scenarios")
async def list_scenarios(engine: SimulationEngine = Depends(get_simulation_engine)) -> dict:
    return {"scenarios": engine.list_scenarios()}


@router.post("")
async def run_simulation(payload: dict, engine: SimulationEngine = Depends(get_simulation_engine)) -> dict:
    scenario = payload.get("scenario")
    if not scenario:
        raise HTTPException(status_code=400, detail="scenario is required")
    params = payload.get("params") or {}
    try:
        logs = engine.run_scenario(scenario, params=params)
        return {"scenario": scenario, "generated_events": len(logs), "logs": logs}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

