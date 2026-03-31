"""AI agent routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.deps import get_agent_orchestrator
from agents.agent_orchestrator import AgentOrchestrator

router = APIRouter(prefix="/agents", tags=["Agents"])


@router.post("/analyze")
async def run_agents(payload: dict, orchestrator: AgentOrchestrator = Depends(get_agent_orchestrator)) -> dict:
    try:
        report = await orchestrator.run_full_analysis(payload)
        return {"ok": True, "report": report}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Agent analysis failed: {exc}") from exc

