"""Analysis API routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.deps import get_rule_engine, get_threat_detector, get_threat_scorer
from detection.rule_engine import RuleEngine
from detection.threat_detector import ThreatDetector
from scoring.threat_scorer import ThreatScorer
from utils.logging_config import get_logger

router = APIRouter(prefix="/analyze", tags=["Analysis"])
logger = get_logger(__name__)


@router.post("")
async def analyze_log(
    payload: dict,
    detector: ThreatDetector = Depends(get_threat_detector),
    rule_engine: RuleEngine = Depends(get_rule_engine),
    scorer: ThreatScorer = Depends(get_threat_scorer),
) -> dict:
    """Run detection pipeline and return scoring analysis."""
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
        return {
            "ok": True,
            "detection": det.to_dict() if det else None,
            "rule_matches": [m.to_dict() for m in rule_matches],
            "threat_score": scored,
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("Analysis failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc

