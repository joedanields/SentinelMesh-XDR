"""Incident Manager – create, track, escalate, and report on incidents."""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_SLA_HOURS = {"low": 72, "medium": 24, "high": 4, "critical": 1}


@dataclass
class TimelineEntry:
    timestamp: str
    action: str
    actor: str
    details: str


@dataclass
class Incident:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    status: str = "open"
    severity: str = "medium"
    alert_ids: List[str] = field(default_factory=list)
    affected_hosts: List[str] = field(default_factory=list)
    timeline: List[TimelineEntry] = field(default_factory=list)
    assigned_to: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    closed_at: Optional[str] = None
    root_cause: Optional[str] = None
    lessons_learned: Optional[str] = None
    sla_deadline: Optional[str] = None
    escalated: bool = False
    resolution: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items()}
        d["timeline"] = [t.__dict__ for t in self.timeline]
        return d


@dataclass
class IncidentReport:
    incident_id: str
    title: str
    generated_at: str
    markdown: str


class IncidentManager:
    """Manages the lifecycle of security incidents."""

    def __init__(self) -> None:
        self._incidents: Dict[str, Incident] = {}

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_incident(
        self,
        alerts: List[Dict[str, Any]],
        title: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Incident:
        severity = self._calculate_severity(alerts)
        alert_ids = [a.get("id", str(uuid.uuid4())) for a in alerts]
        hosts = list({a.get("hostname", "") for a in alerts if a.get("hostname")})
        attack_vectors = list({a.get("attack_vector", "") for a in alerts if a.get("attack_vector")})
        auto_title = title or f"Incident: {', '.join(attack_vectors) or 'Unknown'} detected"
        auto_desc = description or (
            f"Auto-generated incident from {len(alerts)} alert(s). "
            f"Severity: {severity}. Affected hosts: {', '.join(hosts) or 'N/A'}."
        )
        sla_h = _SLA_HOURS.get(severity, 24)
        sla_deadline = (datetime.now(timezone.utc) + timedelta(hours=sla_h)).isoformat()
        incident = Incident(
            title=auto_title,
            description=auto_desc,
            severity=severity,
            alert_ids=alert_ids,
            affected_hosts=hosts,
            sla_deadline=sla_deadline,
        )
        incident.timeline.append(
            TimelineEntry(
                timestamp=incident.created_at,
                action="created",
                actor="system",
                details=f"Incident auto-created from {len(alerts)} alerts",
            )
        )
        self._incidents[incident.id] = incident
        logger.info("Created incident %s severity=%s", incident.id, severity)
        return incident

    def update_incident_status(self, incident_id: str, status: str, actor: str = "system") -> Incident:
        incident = self._get_or_raise(incident_id)
        old_status = incident.status
        incident.status = status
        incident.updated_at = datetime.now(timezone.utc).isoformat()
        if status == "closed" and not incident.closed_at:
            incident.closed_at = incident.updated_at
        incident.timeline.append(
            TimelineEntry(
                timestamp=incident.updated_at,
                action="status_change",
                actor=actor,
                details=f"Status changed from {old_status} to {status}",
            )
        )
        return incident

    def escalate_incident(self, incident_id: str, reason: str, actor: str = "system") -> Incident:
        incident = self._get_or_raise(incident_id)
        old_sev = incident.severity
        rank = _SEVERITY_RANK.get(old_sev, 2)
        sev_list = ["low", "medium", "high", "critical"]
        new_sev = sev_list[min(rank, 3)]
        incident.severity = new_sev
        incident.escalated = True
        incident.updated_at = datetime.now(timezone.utc).isoformat()
        incident.timeline.append(
            TimelineEntry(
                timestamp=incident.updated_at,
                action="escalated",
                actor=actor,
                details=f"Escalated from {old_sev} to {new_sev}. Reason: {reason}",
            )
        )
        logger.warning("Incident %s escalated to %s: %s", incident_id, new_sev, reason)
        return incident

    def assign_incident(self, incident_id: str, user: str, actor: str = "system") -> Incident:
        incident = self._get_or_raise(incident_id)
        incident.assigned_to = user
        incident.updated_at = datetime.now(timezone.utc).isoformat()
        incident.timeline.append(
            TimelineEntry(
                timestamp=incident.updated_at,
                action="assigned",
                actor=actor,
                details=f"Assigned to {user}",
            )
        )
        return incident

    def close_incident(self, incident_id: str, resolution: str, actor: str = "system") -> Incident:
        incident = self._get_or_raise(incident_id)
        incident.resolution = resolution
        incident.status = "closed"
        incident.closed_at = datetime.now(timezone.utc).isoformat()
        incident.updated_at = incident.closed_at
        incident.timeline.append(
            TimelineEntry(
                timestamp=incident.closed_at,
                action="closed",
                actor=actor,
                details=f"Resolution: {resolution}",
            )
        )
        return incident

    def get_incident_timeline(self, incident_id: str) -> List[TimelineEntry]:
        return self._get_or_raise(incident_id).timeline

    def get_incident(self, incident_id: str) -> Incident:
        return self._get_or_raise(incident_id)

    def list_incidents(self, status: Optional[str] = None) -> List[Incident]:
        incidents = list(self._incidents.values())
        if status:
            incidents = [i for i in incidents if i.status == status]
        return sorted(incidents, key=lambda x: x.created_at, reverse=True)

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def generate_incident_report(self, incident_id: str) -> IncidentReport:
        inc = self._get_or_raise(incident_id)
        now = datetime.now(timezone.utc).isoformat()
        lines = [
            f"# Incident Report: {inc.title}",
            f"",
            f"**ID:** `{inc.id}`  ",
            f"**Status:** {inc.status}  ",
            f"**Severity:** {inc.severity.upper()}  ",
            f"**Created:** {inc.created_at}  ",
            f"**Closed:** {inc.closed_at or 'Open'}  ",
            f"**Assigned To:** {inc.assigned_to or 'Unassigned'}  ",
            f"**SLA Deadline:** {inc.sla_deadline or 'N/A'}  ",
            f"",
            f"## Description",
            f"{inc.description}",
            f"",
            f"## Affected Assets",
        ] + [f"- `{h}`" for h in inc.affected_hosts or ["None identified"]] + [
            f"",
            f"## Linked Alerts ({len(inc.alert_ids)})",
        ] + [f"- `{a}`" for a in inc.alert_ids] + [
            f"",
            f"## Timeline",
        ]
        for entry in inc.timeline:
            lines.append(f"| {entry.timestamp} | **{entry.action}** | {entry.actor} | {entry.details} |")
        lines += [
            f"",
            f"## Root Cause",
            inc.root_cause or "_Not yet determined_",
            f"",
            f"## Lessons Learned",
            inc.lessons_learned or "_To be completed after closure_",
            f"",
            f"## Resolution",
            inc.resolution or "_Pending_",
            f"",
            f"---",
            f"_Report generated at {now}_",
        ]
        return IncidentReport(
            incident_id=inc.id,
            title=inc.title,
            generated_at=now,
            markdown="\n".join(lines),
        )

    # ------------------------------------------------------------------
    # Auto-grouping
    # ------------------------------------------------------------------

    def auto_group_alerts(
        self,
        alerts: List[Dict[str, Any]],
        similarity_window_minutes: int = 30,
    ) -> List[Incident]:
        """Group related alerts into incidents by time window and host overlap."""
        if not alerts:
            return []
        alerts_sorted = sorted(alerts, key=lambda a: a.get("timestamp", ""))
        groups: List[List[Dict[str, Any]]] = []
        current_group: List[Dict[str, Any]] = [alerts_sorted[0]]
        for alert in alerts_sorted[1:]:
            last_ts = current_group[-1].get("timestamp", "")
            curr_ts = alert.get("timestamp", "")
            try:
                dt_last = datetime.fromisoformat(last_ts)
                dt_curr = datetime.fromisoformat(curr_ts)
                same_host = alert.get("hostname") in {a.get("hostname") for a in current_group}
                if (dt_curr - dt_last) <= timedelta(minutes=similarity_window_minutes) or same_host:
                    current_group.append(alert)
                    continue
            except (ValueError, TypeError):
                pass
            groups.append(current_group)
            current_group = [alert]
        groups.append(current_group)
        return [self.create_incident(g) for g in groups]

    # ------------------------------------------------------------------
    # SLA tracking
    # ------------------------------------------------------------------

    def check_sla_breaches(self) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc)
        breaches = []
        for inc in self._incidents.values():
            if inc.status == "closed" or not inc.sla_deadline:
                continue
            try:
                deadline = datetime.fromisoformat(inc.sla_deadline)
                if now > deadline:
                    overdue_minutes = (now - deadline).total_seconds() / 60
                    breaches.append({
                        "incident_id": inc.id,
                        "title": inc.title,
                        "severity": inc.severity,
                        "sla_deadline": inc.sla_deadline,
                        "overdue_minutes": round(overdue_minutes, 1),
                    })
            except (ValueError, TypeError):
                pass
        return breaches

    # ------------------------------------------------------------------

    def _get_or_raise(self, incident_id: str) -> Incident:
        inc = self._incidents.get(incident_id)
        if inc is None:
            raise KeyError(f"Incident not found: {incident_id}")
        return inc

    def _calculate_severity(self, alerts: List[Dict[str, Any]]) -> str:
        if not alerts:
            return "low"
        rank = max(_SEVERITY_RANK.get(a.get("severity", "low"), 1) for a in alerts)
        return ["low", "low", "medium", "high", "critical"][rank]
