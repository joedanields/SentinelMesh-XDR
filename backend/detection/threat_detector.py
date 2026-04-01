"""Threat detector – combines rules, anomaly detection, TI lookups, and UBA."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

from .rule_engine import RuleEngine, RuleMatch

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------


@dataclass
class DetectionResult:
    log_id: str
    risk_score: float           # 0 – 100
    severity: str               # info | low | medium | high | critical
    matched_rules: list[RuleMatch]
    reasons: list[str]
    threat_intel_hits: list[dict[str, Any]]
    anomaly_score: float = 0.0
    confidence: float = 0.0
    mitre_techniques: list[str] = field(default_factory=list)
    false_positive_suppressed: bool = False
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "log_id": self.log_id,
            "risk_score": round(self.risk_score, 2),
            "severity": self.severity,
            "matched_rules": [r.to_dict() for r in self.matched_rules],
            "reasons": self.reasons,
            "threat_intel_hits": self.threat_intel_hits,
            "anomaly_score": round(self.anomaly_score, 4),
            "confidence": round(self.confidence, 4),
            "mitre_techniques": self.mitre_techniques,
            "false_positive_suppressed": self.false_positive_suppressed,
            "detected_at": self.detected_at,
        }


# ---------------------------------------------------------------------------
# Keyword threat intelligence (lightweight, no external deps)
# ---------------------------------------------------------------------------

_THREAT_KEYWORDS: dict[str, tuple[str, float]] = {
    # (reason_label, risk_contribution)
    r"(?i)\b(metasploit|meterpreter|cobalt.?strike)\b": ("known_exploit_tool", 30.0),
    r"(?i)\b(mimikatz|lsass|credential.?dump)\b": ("credential_dumping", 35.0),
    r"(?i)\b(ransomware|\.locked|\.crypted|\.encrypted)\b": ("ransomware_indicator", 40.0),
    r"(?i)(\/etc\/shadow|\/etc\/passwd|sam\.hive)": ("sensitive_file_access", 25.0),
    r"(?i)(base64.*eval|eval\(base64|powershell.*-enc)": ("obfuscated_execution", 28.0),
    r"(?i)(wget|curl).*(http|https).*\|.*(bash|sh|python)": ("download_execute_chain", 35.0),
    r"(?i)\b(c2|command.?and.?control|beacon|implant)\b": ("c2_communication", 30.0),
    r"(?i)\b(sql.?injection|union.?select|or.?1.?=.?1)\b": ("sql_injection", 20.0),
    r"(?i)\b(xss|script.?injection|<script|onerror=)\b": ("xss_attempt", 15.0),
    r"(?i)\b(ldap.?injection|log4j|jndi:)\b": ("critical_vulnerability", 40.0),
    r"(?i)\b(privilege.?escalat|sudo.?-i|suid)\b": ("privilege_escalation", 25.0),
    r"(?i)\b(lateral.?movement|pass.?the.?hash|wmiexec)\b": ("lateral_movement", 30.0),
}

_COMPILED_THREAT_KW = {re.compile(pat): info for pat, info in _THREAT_KEYWORDS.items()}


# ---------------------------------------------------------------------------
# Whitelist / false-positive suppression
# ---------------------------------------------------------------------------

_DEFAULT_WHITELIST: list[dict[str, Any]] = [
    {"field": "ip_address", "values": {"127.0.0.1", "::1", "0.0.0.0"}},
    {"field": "user", "values": {"root"}, "event_type_prefix": "ssh_login_success"},  # local root ok
    {"field": "source", "values": {"healthcheck", "monitor", "prometheus"}},
]


def _is_whitelisted(log: dict[str, Any], whitelist: list[dict[str, Any]]) -> bool:
    for entry in whitelist:
        f = entry.get("field", "")
        vals: set = entry.get("values", set())
        if log.get(f) in vals:
            # Check optional event_type prefix constraint
            prefix = entry.get("event_type_prefix")
            if prefix is None or str(log.get("event_type", "")).startswith(prefix):
                return True
    return False


# ---------------------------------------------------------------------------
# Severity / score mapping
# ---------------------------------------------------------------------------

_SEVERITY_THRESHOLDS = [
    (80.0, "critical"),
    (60.0, "high"),
    (40.0, "medium"),
    (20.0, "low"),
    (0.0,  "info"),
]


def _score_to_severity(score: float) -> str:
    for threshold, label in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "info"


_RULE_SEVERITY_SCORES: dict[str, float] = {
    "critical": 35.0,
    "high": 25.0,
    "error": 20.0,
    "warning": 12.0,
    "medium": 12.0,
    "low": 6.0,
    "info": 2.0,
}

# ---------------------------------------------------------------------------
# User Behaviour Analytics – baseline tracker
# ---------------------------------------------------------------------------


class _UBATracker:
    """Lightweight per-user baseline for deviation scoring."""

    def __init__(self, window: int = 3600) -> None:
        """``window`` is the rolling time window in seconds for event counts."""
        import time
        self._window = window
        # user -> list of (monotonic_time, event_type)
        self._events: dict[str, list[tuple[float, str]]] = {}
        self._time = time

    def record(self, user: str, event_type: str) -> None:
        if not user:
            return
        import time as _time
        now = _time.monotonic()
        lst = self._events.setdefault(user, [])
        lst.append((now, event_type))
        cutoff = now - self._window
        self._events[user] = [(t, e) for t, e in lst if t >= cutoff]

    def deviation_score(self, user: str, event_type: str) -> float:
        """Return a 0–1 anomaly score based on how unusual this event_type is for the user."""
        lst = self._events.get(user, [])
        if len(lst) < 10:
            return 0.0  # not enough history
        type_count = sum(1 for _, e in lst if e == event_type)
        ratio = type_count / len(lst)
        # Low ratio → more unusual
        return max(0.0, 1.0 - ratio * 5)


# ---------------------------------------------------------------------------
# ThreatDetector
# ---------------------------------------------------------------------------


class ThreatDetector:
    """Unified threat detector combining multiple detection layers.

    Detection layers (applied in order)
    ------------------------------------
    1. Whitelist check – suppress known-safe events.
    2. Rule-based detection via :class:`RuleEngine`.
    3. Keyword / TI matching against the log text.
    4. IP reputation lookup (via :class:`ThreatIntelligence` if wired up).
    5. User Behaviour Analytics deviation score.
    6. Anomaly score injection (from :class:`AnomalyDetector` if wired up).

    The final ``risk_score`` (0–100) is a weighted sum of contributions.
    """

    def __init__(
        self,
        rule_engine: RuleEngine | None = None,
        threat_intelligence: Any | None = None,   # ThreatIntelligence – avoid circular import
        anomaly_detector: Any | None = None,       # AnomalyDetector
        whitelist: list[dict[str, Any]] | None = None,
        confidence_threshold: float = 0.3,
        min_score_to_alert: float = 10.0,
    ) -> None:
        self.rule_engine = rule_engine or RuleEngine()
        if not self.rule_engine._sorted_rules:
            self.rule_engine.load_builtin_rules()
        self.threat_intelligence = threat_intelligence
        self.anomaly_detector = anomaly_detector
        self.whitelist = whitelist or _DEFAULT_WHITELIST
        self.confidence_threshold = confidence_threshold
        self.min_score_to_alert = min_score_to_alert
        self._uba = _UBATracker()
        self._log = logger.bind(component="ThreatDetector")
        self._total_detections = 0
        self._total_events = 0

    # ------------------------------------------------------------------
    # Main detection entry-point
    # ------------------------------------------------------------------

    def detect(self, log: dict[str, Any]) -> DetectionResult | None:
        """Analyse *log* and return a :class:`DetectionResult` or ``None`` if benign."""
        self._total_events += 1
        log_id = str(log.get("id", ""))
        reasons: list[str] = []
        risk_score = 0.0
        ti_hits: list[dict[str, Any]] = []
        all_matches: list[RuleMatch] = []

        # -- 1. Whitelist --
        if _is_whitelisted(log, self.whitelist):
            return None

        # -- 2. Rule engine --
        rule_matches = self.rule_engine.evaluate_log(log)
        for m in rule_matches:
            contribution = _RULE_SEVERITY_SCORES.get(m.severity, 10.0) * m.confidence
            risk_score += contribution
            reasons.append(f"Rule [{m.rule_name}] matched (conf={m.confidence:.2f})")
            all_matches.append(m)

        # -- 3. Keyword threat intelligence --
        log_text = " ".join(str(v) for v in log.values() if isinstance(v, str))
        for pattern, (label, contrib) in _COMPILED_THREAT_KW.items():
            if pattern.search(log_text):
                risk_score += contrib
                reasons.append(f"Threat keyword: {label}")

        # -- 4. IP reputation --
        ip = str(log.get("ip_address", ""))
        if ip and self.threat_intelligence:
            ti_result = self.threat_intelligence.check_ip(ip)
            if ti_result and ti_result.is_malicious:
                risk_score += 30.0
                reasons.append(f"Malicious IP: {ip} ({ti_result.category})")
                ti_hits.append({"ip": ip, "category": ti_result.category, "score": ti_result.score})

        # -- 5. UBA --
        user = str(log.get("user", ""))
        event_type = str(log.get("event_type", ""))
        if user:
            uba_score = self._uba.deviation_score(user, event_type)
            if uba_score > 0.5:
                contribution = uba_score * 20
                risk_score += contribution
                reasons.append(f"UBA: unusual event type {event_type!r} for user {user!r} (score={uba_score:.2f})")
            self._uba.record(user, event_type)

        # -- 6. Anomaly detector --
        anomaly_score = 0.0
        if self.anomaly_detector:
            try:
                anomaly_score = self.anomaly_detector.score(log)
                if anomaly_score > 0.6:
                    risk_score += anomaly_score * 25
                    reasons.append(f"Statistical anomaly detected (score={anomaly_score:.3f})")
            except Exception as exc:
                self._log.debug("anomaly detector error", error=str(exc))

        # -- Cap score --
        risk_score = min(100.0, risk_score)

        if risk_score < self.min_score_to_alert or not reasons:
            return None

        # -- Confidence aggregation --
        confidence = min(1.0, risk_score / 100.0)
        if confidence < self.confidence_threshold and not rule_matches:
            return None

        severity = _score_to_severity(risk_score)
        mitre = list({m.mitre_technique for m in all_matches if m.mitre_technique})

        self._total_detections += 1
        result = DetectionResult(
            log_id=log_id,
            risk_score=risk_score,
            severity=severity,
            matched_rules=all_matches,
            reasons=reasons,
            threat_intel_hits=ti_hits,
            anomaly_score=anomaly_score,
            confidence=confidence,
            mitre_techniques=mitre,
        )
        self._log.info(
            "threat detected",
            log_id=log_id,
            score=round(risk_score, 1),
            severity=severity,
            reasons=reasons[:3],
        )
        return result

    # ------------------------------------------------------------------
    # Whitelist management
    # ------------------------------------------------------------------

    def add_whitelist_entry(self, field: str, values: list[str]) -> None:
        self.whitelist.append({"field": field, "values": set(values)})

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        return {
            "total_events_processed": self._total_events,
            "total_detections": self._total_detections,
            "detection_rate": round(self._total_detections / max(1, self._total_events), 4),
        }
