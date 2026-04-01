"""Monitoring and metrics routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import (
    get_agent_orchestrator,
    get_anomaly_detector,
    get_db_session,
    get_rule_engine,
    get_simulation_engine,
    get_threat_detector,
)
from agents.agent_orchestrator import AgentOrchestrator
from detection.anomaly_detector import AnomalyDetector
from detection.rule_engine import RuleEngine
from detection.threat_detector import ThreatDetector
from models.alert_models import Alert
from models.incident_models import Incident
from models.log_models import Log
from simulation.simulation_engine import SimulationEngine

router = APIRouter(prefix="/monitoring", tags=["Monitoring"])


@router.get("/metrics")
async def metrics(
    db: AsyncSession = Depends(get_db_session),
    rule_engine: RuleEngine = Depends(get_rule_engine),
    detector: ThreatDetector = Depends(get_threat_detector),
    anomaly: AnomalyDetector = Depends(get_anomaly_detector),
    orchestrator: AgentOrchestrator = Depends(get_agent_orchestrator),
    simulation: SimulationEngine = Depends(get_simulation_engine),
) -> dict[str, Any]:
    logs_count = (await db.execute(select(func.count()).select_from(Log))).scalar_one()
    alerts_count = (await db.execute(select(func.count()).select_from(Alert))).scalar_one()
    incidents_count = (await db.execute(select(func.count()).select_from(Incident))).scalar_one()

    return {
        "database": {
            "logs": logs_count,
            "alerts": alerts_count,
            "incidents": incidents_count,
        },
        "rule_engine": rule_engine.performance_stats(),
        "threat_detector": detector.stats(),
        "anomaly_detector": anomaly.stats(),
        "agent_orchestrator": orchestrator.get_metrics(),
        "simulation": {
            "scenarios": simulation.list_scenarios(),
            "scenario_count": len(simulation.list_scenarios()),
        },
    }
