"""Analysis API routes."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db_session, get_rule_engine, get_threat_detector, get_threat_scorer
from detection.rule_engine import RuleEngine
from detection.threat_detector import ThreatDetector
from models.alert_models import Alert, AlertSeverity, AlertStatus
from models.incident_models import Incident, IncidentSeverity, IncidentStatus
from models.log_models import Log
from scoring.threat_scorer import ThreatScorer
from utils.logging_config import get_logger

router = APIRouter(prefix="/analyze", tags=["Analysis"])
logger = get_logger(__name__)


def _as_alert_severity(value: str | None) -> AlertSeverity:
    val = (value or "medium").lower()
    if val in AlertSeverity._value2member_map_:
        return AlertSeverity(val)
    if val in {"info", "warning", "error"}:
        return AlertSeverity.medium if val in {"warning", "error"} else AlertSeverity.low
    return AlertSeverity.medium


def _as_incident_severity(value: str | None) -> IncidentSeverity:
    val = (value or "medium").lower()
    if val in IncidentSeverity._value2member_map_:
        return IncidentSeverity(val)
    if val in {"info", "warning"}:
        return IncidentSeverity.low
    if val == "error":
        return IncidentSeverity.medium
    return IncidentSeverity.medium


def _persist_analysis_artifacts(
    db: AsyncSession,
    payload: dict[str, Any],
    detection: dict[str, Any] | None,
    score: dict[str, Any],
) -> tuple[Alert | None, Incident | None]:
    if detection is None:
        return None, None

    severity = _as_alert_severity(detection.get("severity"))
    risk_score = float(detection.get("risk_score") or score.get("score") or 0.0)
    confidence = float(detection.get("confidence") or 0.5)

    title = f"Threat detected: {payload.get('event_type') or payload.get('source') or 'unknown_event'}"
    description = "; ".join(detection.get("reasons") or [])[:2000] or "Rule-based threat detection triggered."

    alert = Alert(
        title=title,
        description=description,
        severity=severity,
        status=AlertStatus.new,
        rule_id=(detection.get("matched_rules") or [{}])[0].get("rule_id") if detection.get("matched_rules") else None,
        log_ids=[str(payload.get("id", ""))] if payload.get("id") else [],
        risk_score=risk_score,
        confidence=confidence,
        mitre_technique=(detection.get("mitre_techniques") or [None])[0],
        tags=["auto_generated", "rule_based_detection"],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(alert)

    incident: Incident | None = None
    if severity in {AlertSeverity.high, AlertSeverity.critical}:
        incident = Incident(
            title=f"Incident from alert: {title}",
            description=description,
            status=IncidentStatus.open,
            severity=_as_incident_severity(severity.value),
            alert_ids=[],
            affected_hosts=[payload.get("host")] if payload.get("host") else [],
            timeline=[
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "action": "created",
                    "actor": "analyze_api",
                    "details": "Incident auto-created from high-severity detection",
                }
            ],
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(incident)

    return alert, incident


@router.post("")
async def analyze_log(
    payload: dict,
    detector: ThreatDetector = Depends(get_threat_detector),
    rule_engine: RuleEngine = Depends(get_rule_engine),
    scorer: ThreatScorer = Depends(get_threat_scorer),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """Run rule + pattern + anomaly analysis and persist alert/incident artifacts."""
    try:
        rule_matches = rule_engine.evaluate_log(payload)
        det = detector.detect(payload)
        anomaly_score = float(det.anomaly_score) if det else 0.0
        ti_hits = det.threat_intel_hits if det else []

        scored = scorer.score(
            log_data=payload,
            rule_matches=[m.to_dict() for m in rule_matches],
            anomaly_score=anomaly_score,
            threat_intel_hits=ti_hits,
        )

        alert = None
        incident = None
        if det:
            alert, incident = _persist_analysis_artifacts(db, payload, det.to_dict(), scored)
            if alert:
                await db.flush()
                if incident:
                    incident.alert_ids = [alert.id]
                await db.refresh(alert)
                if incident:
                    await db.refresh(incident)

        return {
            "ok": True,
            "detection": det.to_dict() if det else None,
            "rule_matches": [m.to_dict() for m in rule_matches],
            "threat_score": scored,
            "alert": {
                "id": alert.id,
                "severity": alert.severity.value,
                "status": alert.status.value,
            } if alert else None,
            "incident": {
                "id": incident.id,
                "severity": incident.severity.value,
                "status": incident.status.value,
            } if incident else None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("Analysis failed", error=str(exc))
        raise HTTPException(status_code=500, detail="Analysis pipeline failed") from exc
