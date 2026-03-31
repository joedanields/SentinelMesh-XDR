"""Dependency wiring for SentinelMesh XDR API."""
from __future__ import annotations

from functools import lru_cache
from typing import AsyncGenerator

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from agents.agent_orchestrator import AgentOrchestrator
from detection.rule_engine import RuleEngine
from detection.threat_detector import ThreatDetector
from incident_response.alert_manager import AlertManager
from incident_response.incident_manager import IncidentManager
from models.database import get_db
from scoring.threat_scorer import ThreatScorer
from simulation.simulation_engine import SimulationEngine
from utils.logging_config import get_logger

logger = get_logger(__name__)
security = HTTPBearer(auto_error=False)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async for db in get_db():
        yield db


@lru_cache()
def get_rule_engine() -> RuleEngine:
    eng = RuleEngine()
    eng.load_builtin_rules()
    return eng


@lru_cache()
def get_threat_detector() -> ThreatDetector:
    return ThreatDetector(rule_engine=get_rule_engine())


@lru_cache()
def get_agent_orchestrator() -> AgentOrchestrator:
    return AgentOrchestrator()


@lru_cache()
def get_simulation_engine() -> SimulationEngine:
    return SimulationEngine()


@lru_cache()
def get_incident_manager() -> IncidentManager:
    return IncidentManager()


@lru_cache()
def get_alert_manager() -> AlertManager:
    return AlertManager()


@lru_cache()
def get_threat_scorer() -> ThreatScorer:
    return ThreatScorer()


def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> dict:
    """Auth placeholder until full identity integration is completed."""
    if credentials is None:
        return {"username": "anonymous", "role": "viewer"}
    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return {"username": "analyst", "role": "analyst", "token": token}

