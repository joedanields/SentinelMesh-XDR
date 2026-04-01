"""Threat scoring engine for SentinelMesh XDR."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from utils.logging_config import get_logger

logger = get_logger(__name__)


class ThreatScorer:
    """Dynamic and explainable threat scoring with configurable weights."""

    DEFAULT_WEIGHTS: dict[str, float] = {
        "severity": 0.25,
        "frequency": 0.2,
        "historical_behavior": 0.2,
        "anomaly_deviation": 0.2,
        "threat_intel": 0.15,
    }

    SEVERITY_MAP: dict[str, float] = {
        "info": 10.0,
        "low": 25.0,
        "warning": 40.0,
        "medium": 55.0,
        "high": 75.0,
        "critical": 95.0,
        "error": 70.0,
    }

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        freq_window_size: int = 5000,
    ) -> None:
        self.weights = dict(self.DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(weights)
        self._normalize_weights()
        self._event_history: list[dict[str, Any]] = []
        self._freq_window_size = max(100, freq_window_size)
        self._entity_baseline: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        logger.info("ThreatScorer initialized", weights=self.weights)

    def _normalize_weights(self) -> None:
        total = sum(max(0.0, v) for v in self.weights.values())
        if total <= 0:
            self.weights = dict(self.DEFAULT_WEIGHTS)
            total = sum(self.weights.values())
        for key in list(self.weights.keys()):
            self.weights[key] = max(0.0, self.weights[key]) / total

    # ----------------------------
    # Public scoring API
    # ----------------------------

    def score(
        self,
        *,
        log_data: dict[str, Any],
        rule_matches: list[dict[str, Any]] | None = None,
        anomaly_score: float | None = None,
        threat_intel_hits: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Compute threat score (0-100) with explainable factors."""
        rule_matches = rule_matches or []
        threat_intel_hits = threat_intel_hits or []

        severity_factor = self._severity_factor(log_data, rule_matches)
        frequency_factor = self._frequency_factor(log_data)
        historical_factor = self._historical_behavior_factor(log_data)
        anomaly_factor = self._anomaly_factor(anomaly_score)
        intel_factor = self._threat_intel_factor(threat_intel_hits)

        factor_values = {
            "severity": severity_factor,
            "frequency": frequency_factor,
            "historical_behavior": historical_factor,
            "anomaly_deviation": anomaly_factor,
            "threat_intel": intel_factor,
        }

        score = 0.0
        for key, value in factor_values.items():
            score += self.weights.get(key, 0.0) * value

        score = round(max(0.0, min(100.0, score)), 2)
        level = self._risk_level(score)

        self._record_event(log_data)
        explanation = self._build_explanation(level, score, factor_values, rule_matches, threat_intel_hits)

        result = {
            "score": score,
            "level": level,
            "factors": factor_values,
            "weights": self.weights,
            "explanation": explanation,
        }
        logger.info("Threat scored", score=score, level=level, factors=factor_values)
        return result

    # ----------------------------
    # Factor calculations
    # ----------------------------

    def _severity_factor(self, log_data: dict[str, Any], rule_matches: list[dict[str, Any]]) -> float:
        sev = str(log_data.get("severity", "info")).lower()
        base = self.SEVERITY_MAP.get(sev, 20.0)
        if rule_matches:
            rm_scores = []
            for match in rule_matches:
                m_sev = str(match.get("severity", sev)).lower()
                conf = float(match.get("confidence", 0.7))
                rm_scores.append(self.SEVERITY_MAP.get(m_sev, 35.0) * max(0.0, min(conf, 1.0)))
            base = min(100.0, base + (sum(rm_scores) / max(1, len(rm_scores))) * 0.5)
        return round(base, 2)

    def _frequency_factor(self, log_data: dict[str, Any]) -> float:
        source = str(log_data.get("source", "unknown"))
        event_type = str(log_data.get("event_type", "unknown"))
        now = self._parse_ts(log_data.get("timestamp")) or datetime.now(timezone.utc)
        cutoff = now.timestamp() - 300  # five minutes
        recent = [
            e for e in self._event_history
            if e["source"] == source and e["event_type"] == event_type and e["ts"] >= cutoff
        ]
        count = len(recent) + 1
        if count <= 2:
            return 20.0
        if count <= 5:
            return 45.0
        if count <= 10:
            return 70.0
        return 90.0

    def _historical_behavior_factor(self, log_data: dict[str, Any]) -> float:
        user = str(log_data.get("user") or log_data.get("user_id") or "unknown")
        event_type = str(log_data.get("event_type", "unknown"))
        host = str(log_data.get("host", "unknown"))
        key = f"{user}@{host}"
        baseline = self._entity_baseline[key]
        total = sum(baseline.values())
        if total < 20:
            return 30.0
        ratio = baseline.get(event_type, 0) / max(1, total)
        if ratio >= 0.2:
            return 20.0
        if ratio >= 0.05:
            return 45.0
        if ratio >= 0.02:
            return 65.0
        return 85.0

    def _anomaly_factor(self, anomaly_score: float | None) -> float:
        if anomaly_score is None:
            return 25.0
        val = max(0.0, float(anomaly_score))
        if val <= 1.0:
            return round(val * 100.0, 2)
        return round(min(100.0, val), 2)

    def _threat_intel_factor(self, threat_intel_hits: list[dict[str, Any]]) -> float:
        if not threat_intel_hits:
            return 10.0
        scores = []
        for hit in threat_intel_hits:
            h_score = hit.get("score")
            if h_score is None:
                h_score = 70.0
            try:
                val = float(h_score)
            except (ValueError, TypeError):
                val = 70.0
            if val <= 1.0:
                val *= 100.0
            scores.append(max(0.0, min(100.0, val)))
        return round(sum(scores) / len(scores), 2)

    # ----------------------------
    # Utility + state
    # ----------------------------

    def _record_event(self, log_data: dict[str, Any]) -> None:
        source = str(log_data.get("source", "unknown"))
        event_type = str(log_data.get("event_type", "unknown"))
        ts = self._parse_ts(log_data.get("timestamp"))
        now_ts = ts.timestamp() if ts else datetime.now(timezone.utc).timestamp()
        self._event_history.append({"source": source, "event_type": event_type, "ts": now_ts})
        if len(self._event_history) > self._freq_window_size:
            self._event_history = self._event_history[-self._freq_window_size :]

        user = str(log_data.get("user") or log_data.get("user_id") or "unknown")
        host = str(log_data.get("host", "unknown"))
        key = f"{user}@{host}"
        self._entity_baseline[key][event_type] += 1

    @staticmethod
    def _parse_ts(value: Any) -> datetime | None:
        if isinstance(value, datetime):
            return value
        if not value:
            return None
        try:
            txt = str(value).replace("Z", "+00:00")
            return datetime.fromisoformat(txt)
        except Exception:
            return None

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 40:
            return "Medium"
        return "Low"

    def _build_explanation(
        self,
        level: str,
        score: float,
        factors: dict[str, float],
        rule_matches: list[dict[str, Any]],
        threat_intel_hits: list[dict[str, Any]],
    ) -> str:
        top_factor = max(factors.items(), key=lambda i: i[1])[0]
        parts = [
            f"Overall risk is {level} ({score}/100).",
            f"Dominant factor: {top_factor}={factors[top_factor]:.2f}.",
        ]
        if rule_matches:
            parts.append(f"{len(rule_matches)} rule match(es) contributed to severity.")
        if threat_intel_hits:
            parts.append(f"{len(threat_intel_hits)} threat-intelligence hit(s) elevated risk.")
        return " ".join(parts)

