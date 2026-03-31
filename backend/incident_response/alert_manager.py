"""Alert Manager – create, deduplicate, prioritize, and lifecycle alerts."""
from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SLA_HOURS = {"low": 24, "medium": 8, "high": 2, "critical": 0.25}
_SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Alert:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: str = "medium"
    status: str = "new"
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    attack_vector: Optional[str] = None
    mitre_technique: Optional[str] = None
    confidence: float = 0.8
    risk_score: float = 0.0
    tags: List[str] = field(default_factory=list)
    raw_log_id: Optional[str] = None
    assigned_to: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolved_at: Optional[str] = None
    sla_deadline: Optional[str] = None
    dedupe_hash: Optional[str] = None
    priority_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


class AlertManager:
    """Manages the full alert lifecycle with deduplication and prioritization."""

    def __init__(self, similarity_threshold: float = 0.85) -> None:
        self._alerts: Dict[str, Alert] = {}
        self._dedupe_index: Dict[str, str] = {}  # hash -> alert_id
        self.similarity_threshold = similarity_threshold

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create_alert(
        self,
        detection_result: Dict[str, Any],
        log: Dict[str, Any],
    ) -> Optional[Alert]:
        severity = detection_result.get("severity", log.get("severity", "medium"))
        confidence = float(detection_result.get("confidence", 0.8))
        attack_vector = log.get("attack_vector", detection_result.get("attack_vector", "unknown"))
        title = detection_result.get("title") or f"{attack_vector.replace('_', ' ').title()} Detected"
        desc = detection_result.get("description") or (
            f"Detection rule triggered for {attack_vector} from {log.get('source_ip','?')} "
            f"targeting {log.get('hostname','?')}"
        )
        dedupe_hash = self._compute_dedupe_hash(log, severity, attack_vector)
        if dedupe_hash in self._dedupe_index:
            existing_id = self._dedupe_index[dedupe_hash]
            logger.debug("Deduplicated alert %s (existing: %s)", dedupe_hash[:8], existing_id)
            return self._alerts.get(existing_id)

        sla_h = _SLA_HOURS.get(severity, 8)
        sla_deadline = (datetime.now(timezone.utc) + timedelta(hours=sla_h)).isoformat()
        alert = Alert(
            title=title,
            description=desc,
            severity=severity,
            source_ip=log.get("source_ip"),
            dest_ip=log.get("dest_ip"),
            hostname=log.get("hostname"),
            username=log.get("username"),
            attack_vector=attack_vector,
            mitre_technique=log.get("mitre_technique", detection_result.get("mitre_technique")),
            confidence=confidence,
            tags=list(detection_result.get("tags", [])),
            raw_log_id=log.get("id"),
            sla_deadline=sla_deadline,
            dedupe_hash=dedupe_hash,
        )
        alert.priority_score = self._compute_priority(alert)
        self._alerts[alert.id] = alert
        self._dedupe_index[dedupe_hash] = alert.id
        logger.info("Created alert %s [%s] %s", alert.id[:8], severity.upper(), title)
        return alert

    # ------------------------------------------------------------------
    # Prioritization
    # ------------------------------------------------------------------

    def prioritize_alerts(self, alerts: Optional[List[Alert]] = None) -> List[Alert]:
        """Sort alerts by priority score (descending)."""
        items = alerts if alerts is not None else list(self._alerts.values())
        for alert in items:
            alert.priority_score = self._compute_priority(alert)
        return sorted(items, key=lambda a: a.priority_score, reverse=True)

    def _compute_priority(self, alert: Alert) -> float:
        severity_w = _SEVERITY_WEIGHT.get(alert.severity, 2) / 4.0
        confidence_w = alert.confidence
        now = datetime.now(timezone.utc)
        try:
            created = datetime.fromisoformat(alert.created_at)
            age_hours = (now - created).total_seconds() / 3600
        except (ValueError, TypeError):
            age_hours = 0.0
        age_factor = max(0.1, 1.0 - (age_hours / 48.0))
        source_diversity = 1.0  # single source; would scale with multi-source correlation
        return round(severity_w * confidence_w * age_factor * source_diversity * 100, 2)

    # ------------------------------------------------------------------
    # Grouping / clustering
    # ------------------------------------------------------------------

    def group_alerts(self, time_window_minutes: int = 30) -> List[List[Alert]]:
        """Cluster related alerts by host + time proximity."""
        sorted_alerts = sorted(
            self._alerts.values(),
            key=lambda a: a.created_at,
        )
        groups: List[List[Alert]] = []
        current: List[Alert] = []
        for alert in sorted_alerts:
            if not current:
                current.append(alert)
                continue
            last = current[-1]
            try:
                dt_last = datetime.fromisoformat(last.created_at)
                dt_curr = datetime.fromisoformat(alert.created_at)
                time_close = (dt_curr - dt_last) <= timedelta(minutes=time_window_minutes)
                host_match = alert.hostname and alert.hostname == last.hostname
                if time_close or host_match:
                    current.append(alert)
                    continue
            except (ValueError, TypeError):
                pass
            groups.append(current)
            current = [alert]
        if current:
            groups.append(current)
        return groups

    # ------------------------------------------------------------------
    # Lifecycle transitions
    # ------------------------------------------------------------------

    def update_status(self, alert_id: str, status: str, actor: str = "system") -> Alert:
        alert = self._get_or_raise(alert_id)
        alert.status = status
        alert.updated_at = datetime.now(timezone.utc).isoformat()
        if status in ("resolved", "false_positive"):
            alert.resolved_at = alert.updated_at
        logger.info("Alert %s status -> %s by %s", alert_id[:8], status, actor)
        return alert

    def assign_alert(self, alert_id: str, user: str) -> Alert:
        alert = self._get_or_raise(alert_id)
        alert.assigned_to = user
        alert.updated_at = datetime.now(timezone.utc).isoformat()
        return alert

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_alert(self, alert_id: str) -> Alert:
        return self._get_or_raise(alert_id)

    def list_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Alert]:
        alerts = list(self._alerts.values())
        if status:
            alerts = [a for a in alerts if a.status == status]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return self.prioritize_alerts(alerts)[:limit]

    def check_sla_breaches(self) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc)
        breaches = []
        for alert in self._alerts.values():
            if alert.status in ("resolved", "false_positive") or not alert.sla_deadline:
                continue
            try:
                deadline = datetime.fromisoformat(alert.sla_deadline)
                if now > deadline:
                    overdue = (now - deadline).total_seconds() / 60
                    breaches.append({
                        "alert_id": alert.id,
                        "title": alert.title,
                        "severity": alert.severity,
                        "overdue_minutes": round(overdue, 1),
                    })
            except (ValueError, TypeError):
                pass
        return breaches

    def dispatch_notification(self, alert: Alert) -> None:
        """Log-based notification dispatch (production would send email/Slack/PagerDuty)."""
        logger.warning(
            "[NOTIFICATION] %s alert: %s | Source: %s | Host: %s | SLA: %s",
            alert.severity.upper(),
            alert.title,
            alert.source_ip or "?",
            alert.hostname or "?",
            alert.sla_deadline or "N/A",
        )

    # ------------------------------------------------------------------

    def _get_or_raise(self, alert_id: str) -> Alert:
        alert = self._alerts.get(alert_id)
        if alert is None:
            raise KeyError(f"Alert not found: {alert_id}")
        return alert

    @staticmethod
    def _compute_dedupe_hash(log: Dict[str, Any], severity: str, attack_vector: str) -> str:
        key = (
            f"{log.get('source_ip','')}:{log.get('dest_ip','')}:"
            f"{log.get('hostname','')}:{attack_vector}:{severity}"
        )
        return hashlib.sha256(key.encode()).hexdigest()
