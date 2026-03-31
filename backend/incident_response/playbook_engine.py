"""Playbook engine with 10 built-in response playbooks."""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PlaybookStep:
    step_id: str
    name: str
    action_type: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 60
    on_success: Optional[str] = None
    on_failure: Optional[str] = None


@dataclass
class Playbook:
    id: str
    name: str
    description: str
    trigger_conditions: List[str]
    steps: List[PlaybookStep]
    priority: int = 5


@dataclass
class StepResult:
    step_id: str
    step_name: str
    status: str  # success | failure | skipped
    output: str
    duration_ms: float
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class PlaybookResult:
    execution_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    playbook_id: str = ""
    playbook_name: str = ""
    incident_id: str = ""
    status: str = "pending"
    step_results: List[StepResult] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    total_steps: int = 0
    successful_steps: int = 0
    failed_steps: int = 0


def _step(sid: str, name: str, action: str, params: Dict[str, Any] = None,
          timeout: int = 60, on_success: str = None, on_failure: str = None) -> PlaybookStep:
    return PlaybookStep(
        step_id=sid, name=name, action_type=action,
        parameters=params or {}, timeout=timeout,
        on_success=on_success, on_failure=on_failure,
    )


# ---------------------------------------------------------------------------
# Built-in playbook definitions
# ---------------------------------------------------------------------------

BUILTIN_PLAYBOOKS: List[Playbook] = [

    Playbook(
        id="pb-brute-force",
        name="BruteForcePlaybook",
        description="Respond to credential brute force attacks",
        trigger_conditions=["attack_vector:brute_force", "failed_auth_count>10"],
        priority=2,
        steps=[
            _step("s1", "Block Attacker IP", "block_ip", {"duration_hours": 24}),
            _step("s2", "Notify Affected User", "notify_user", {"channel": "email"}),
            _step("s3", "Force Password Reset", "reset_credentials", {}),
            _step("s4", "Increase Monitoring", "increase_monitoring", {"duration_hours": 48}),
            _step("s5", "Create Firewall Rule", "firewall_rule", {"action": "deny"}),
        ],
    ),

    Playbook(
        id="pb-malware",
        name="MalwarePlaybook",
        description="Contain and eradicate malware infection",
        trigger_conditions=["event_type:malware_detection"],
        priority=1,
        steps=[
            _step("s1", "Isolate Infected Host", "isolate_host", {"quarantine": True}),
            _step("s2", "Collect Forensic Evidence", "collect_evidence", {"full_disk_image": False}),
            _step("s3", "Scan Network for IoCs", "scan_network", {}),
            _step("s4", "Kill Malicious Processes", "kill_process", {}),
            _step("s5", "Remove Malicious Files", "delete_file", {}),
            _step("s6", "Patch Vulnerability", "patch_system", {}),
        ],
    ),

    Playbook(
        id="pb-data-breach",
        name="DataBreachPlaybook",
        description="Respond to confirmed data exfiltration",
        trigger_conditions=["attack_vector:data_exfiltration", "bytes_sent>10485760"],
        priority=1,
        steps=[
            _step("s1", "Block Exfiltration Channel", "block_exfiltration", {}),
            _step("s2", "Notify Management", "notify_management", {"urgency": "critical"}),
            _step("s3", "Preserve Log Evidence", "preserve_logs", {"retention_days": 365}),
            _step("s4", "Identify Exfiltrated Data", "data_classification", {}),
            _step("s5", "Notify Regulatory Bodies", "regulatory_notification", {"deadline_hours": 72}),
            _step("s6", "Revoke Compromised Credentials", "reset_credentials", {}),
        ],
    ),

    Playbook(
        id="pb-phishing",
        name="PhishingPlaybook",
        description="Respond to phishing attack",
        trigger_conditions=["event_type:phishing"],
        priority=3,
        steps=[
            _step("s1", "Quarantine Phishing Email", "quarantine_email", {}),
            _step("s2", "Reset User Credentials", "reset_credentials", {}),
            _step("s3", "Scan Email Attachments", "scan_attachments", {}),
            _step("s4", "Block Phishing Domain", "block_domain", {}),
            _step("s5", "User Awareness Alert", "notify_user", {"template": "phishing_awareness"}),
        ],
    ),

    Playbook(
        id="pb-insider-threat",
        name="InsiderThreatPlaybook",
        description="Respond to potential insider threat activity",
        trigger_conditions=["user_risk_score>80", "anomalous_access:true"],
        priority=2,
        steps=[
            _step("s1", "Increase User Monitoring", "increase_monitoring", {"level": "maximum"}),
            _step("s2", "Flag Account for Review", "flag_account", {"review_required": True}),
            _step("s3", "Audit Recent Access", "audit_access", {"days_back": 30}),
            _step("s4", "Restrict Sensitive Access", "revoke_privileges", {"temp": True}),
            _step("s5", "Legal / HR Notification", "legal_notification", {}),
        ],
    ),

    Playbook(
        id="pb-ransomware",
        name="RansomwarePlaybook",
        description="Emergency response to ransomware outbreak",
        trigger_conditions=["event_type:ransomware", "file_encryption_detected:true"],
        priority=1,
        steps=[
            _step("s1", "Isolate Network Segment", "isolate_network_segment", {"emergency": True}),
            _step("s2", "Snapshot All Systems", "snapshot_systems", {}),
            _step("s3", "Activate Backup Recovery", "activate_backups", {}),
            _step("s4", "Identify Patient Zero", "forensic_analysis", {}),
            _step("s5", "Block C2 Communications", "block_ip", {"block_all_unknown": True}),
            _step("s6", "Notify Incident Response Team", "notify_management", {"urgency": "critical"}),
        ],
    ),

    Playbook(
        id="pb-lateral-movement",
        name="LateralMovementPlaybook",
        description="Contain attacker moving laterally through network",
        trigger_conditions=["attack_vector:lateral_movement"],
        priority=1,
        steps=[
            _step("s1", "Revoke All Active Tokens", "revoke_tokens", {}),
            _step("s2", "Audit Active Sessions", "audit_sessions", {}),
            _step("s3", "Scan for Persistence Mechanisms", "scan_for_persistence", {}),
            _step("s4", "Reset Compromised Credentials", "reset_credentials", {"all_affected": True}),
            _step("s5", "Enable Enhanced Logging", "increase_monitoring", {"level": "verbose"}),
            _step("s6", "Segment Affected Hosts", "isolate_host", {"network_only": True}),
        ],
    ),

    Playbook(
        id="pb-ddos",
        name="DDOSPlaybook",
        description="Mitigate distributed denial-of-service attack",
        trigger_conditions=["event_type:ddos", "connection_rate>10000"],
        priority=2,
        steps=[
            _step("s1", "Enable Rate Limiting", "rate_limit", {"threshold_rps": 100}),
            _step("s2", "Geo-Block Attack Sources", "geo_block", {}),
            _step("s3", "Notify ISP / Upstream", "notify_isp", {}),
            _step("s4", "Activate CDN Scrubbing", "cdn_scrubbing", {"enabled": True}),
            _step("s5", "Scale Infrastructure", "auto_scale", {"factor": 3}),
        ],
    ),

    Playbook(
        id="pb-sql-injection",
        name="SQLInjectionPlaybook",
        description="Respond to SQL injection attack on web application",
        trigger_conditions=["attack_vector:sql_injection"],
        priority=2,
        steps=[
            _step("s1", "Block Attacker IP", "block_ip", {"duration_hours": 48}),
            _step("s2", "Enable WAF Rules", "patch_application", {"waf": True}),
            _step("s3", "Review Affected Queries", "review_queries", {}),
            _step("s4", "Audit Database Access Logs", "audit_access", {}),
            _step("s5", "Parameterize Queries", "patch_application", {"code_fix": "parameterized_queries"}),
        ],
    ),

    Playbook(
        id="pb-privilege-escalation",
        name="PrivilegeEscalationPlaybook",
        description="Respond to privilege escalation attempt",
        trigger_conditions=["event_type:privilege_escalation"],
        priority=1,
        steps=[
            _step("s1", "Revoke Elevated Privileges", "revoke_privileges", {}),
            _step("s2", "Audit Privilege Changes", "audit_access", {"scope": "privilege_changes"}),
            _step("s3", "Review Sudo / Admin Config", "review_sudoers", {}),
            _step("s4", "Kill Suspicious Sessions", "kill_process", {"target": "elevated_sessions"}),
            _step("s5", "Force Re-authentication", "reset_credentials", {}),
            _step("s6", "Patch Escalation Vector", "patch_system", {}),
        ],
    ),
]


# ---------------------------------------------------------------------------

class PlaybookEngine:
    """Execute response playbooks against incidents."""

    def __init__(self) -> None:
        self._playbooks: Dict[str, Playbook] = {pb.id: pb for pb in BUILTIN_PLAYBOOKS}

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        return self._playbooks.get(playbook_id)

    def list_playbooks(self) -> List[Playbook]:
        return sorted(self._playbooks.values(), key=lambda p: p.priority)

    def register_playbook(self, playbook: Playbook) -> None:
        self._playbooks[playbook.id] = playbook

    def recommend_playbooks(self, incident: Any) -> List[Playbook]:
        """Return playbooks matching the incident's attack vectors / event types."""
        tags: set = set()
        if hasattr(incident, "severity"):
            tags.add(f"severity:{incident.severity}")
        matches = []
        for pb in self._playbooks.values():
            for cond in pb.trigger_conditions:
                key = cond.split(">")[0].split(":")[0]
                if any(key in str(tag) for tag in tags):
                    matches.append(pb)
                    break
        return sorted(matches, key=lambda p: p.priority) or [self._playbooks.get("pb-malware")]

    def execute_playbook(self, incident: Any, playbook_id: str) -> PlaybookResult:
        import time
        pb = self._playbooks.get(playbook_id)
        if pb is None:
            raise KeyError(f"Playbook not found: {playbook_id}")
        incident_id = getattr(incident, "id", str(uuid.uuid4()))
        result = PlaybookResult(
            playbook_id=pb.id,
            playbook_name=pb.name,
            incident_id=incident_id,
            status="running",
            total_steps=len(pb.steps),
        )
        logger.info("Executing playbook '%s' for incident %s", pb.name, incident_id)

        for step in pb.steps:
            t0 = time.monotonic()
            try:
                output = self._execute_step(step, incident)
                status = "success"
                result.successful_steps += 1
            except Exception as exc:
                output = f"Step failed: {exc}"
                status = "failure"
                result.failed_steps += 1
                logger.error("Playbook %s step %s failed: %s", pb.id, step.step_id, exc)

            duration_ms = (time.monotonic() - t0) * 1000
            result.step_results.append(
                StepResult(
                    step_id=step.step_id,
                    step_name=step.name,
                    status=status,
                    output=output,
                    duration_ms=round(duration_ms, 2),
                )
            )

            if status == "failure" and step.on_failure == "abort":
                result.status = "aborted"
                break
        else:
            result.status = "completed" if result.failed_steps == 0 else "completed_with_errors"

        result.completed_at = datetime.now(timezone.utc).isoformat()
        logger.info(
            "Playbook '%s' finished: %s (%d/%d steps ok)",
            pb.name, result.status, result.successful_steps, result.total_steps,
        )
        return result

    # ------------------------------------------------------------------

    def _execute_step(self, step: PlaybookStep, incident: Any) -> str:
        """Simulate execution of a playbook action (logs what would happen)."""
        action = step.action_type
        params = step.parameters
        incident_id = getattr(incident, "id", "unknown")

        _action_messages: Dict[str, str] = {
            "block_ip": f"[SIMULATED] Blocked attacker IP for {params.get('duration_hours', 24)}h via firewall rule",
            "notify_user": f"[SIMULATED] Email notification sent to affected user(s) via {params.get('channel','email')}",
            "reset_credentials": "[SIMULATED] Password reset link sent; active sessions revoked",
            "increase_monitoring": f"[SIMULATED] Enhanced monitoring enabled for {params.get('duration_hours', 24)}h at level {params.get('level','standard')}",
            "isolate_host": f"[SIMULATED] Host quarantined - network access {'blocked' if params.get('quarantine') else 'restricted'}",
            "collect_evidence": "[SIMULATED] Memory dump and log archive collected to evidence store",
            "scan_network": "[SIMULATED] Network-wide IOC scan initiated",
            "quarantine_email": "[SIMULATED] Email quarantined and moved to admin review folder",
            "scan_attachments": "[SIMULATED] Attachments submitted to sandbox for analysis",
            "block_domain": "[SIMULATED] Phishing domain added to DNS blocklist",
            "flag_account": "[SIMULATED] Account flagged for security review",
            "audit_access": f"[SIMULATED] Access audit initiated for past {params.get('days_back', 7)} days",
            "revoke_privileges": "[SIMULATED] Elevated privileges revoked; user demoted to standard role",
            "legal_notification": "[SIMULATED] Legal and HR teams notified per insider threat policy",
            "isolate_network_segment": "[SIMULATED] VLAN isolated; inter-segment traffic blocked",
            "snapshot_systems": "[SIMULATED] VM snapshots triggered across affected segment",
            "activate_backups": "[SIMULATED] Backup restoration job queued",
            "revoke_tokens": "[SIMULATED] All OAuth tokens and Kerberos tickets invalidated",
            "audit_sessions": "[SIMULATED] Active session audit report generated",
            "scan_for_persistence": "[SIMULATED] Persistence scan running (scheduled tasks, services, registry)",
            "rate_limit": f"[SIMULATED] Rate limiting enabled at {params.get('threshold_rps', 500)} req/s",
            "geo_block": "[SIMULATED] Geo-block rules applied for identified attack source regions",
            "notify_isp": "[SIMULATED] ISP notified with attack traffic details",
            "patch_application": "[SIMULATED] Emergency patch/WAF rule applied to application",
            "review_queries": "[SIMULATED] Database query audit report generated",
            "review_sudoers": "[SIMULATED] sudoers and admin group membership reviewed",
            "kill_process": "[SIMULATED] Malicious process terminated",
            "patch_system": "[SIMULATED] System vulnerability patched",
            "delete_file": "[SIMULATED] Malicious files removed from quarantine",
            "firewall_rule": f"[SIMULATED] Firewall rule created: {params.get('action','deny')} inbound",
            "block_exfiltration": "[SIMULATED] Outbound data channels to unknown IPs blocked",
            "notify_management": f"[SIMULATED] Management notified with urgency={params.get('urgency','high')}",
            "preserve_logs": f"[SIMULATED] Logs preserved for {params.get('retention_days', 90)} days",
            "data_classification": "[SIMULATED] Data classification scan run on accessed files",
            "regulatory_notification": f"[SIMULATED] Regulatory notification prepared (deadline {params.get('deadline_hours',72)}h)",
            "cdn_scrubbing": "[SIMULATED] CDN traffic scrubbing activated",
            "auto_scale": f"[SIMULATED] Infrastructure scaled by factor {params.get('factor', 2)}x",
            "forensic_analysis": "[SIMULATED] Forensic analysis task queued for patient-zero identification",
        }

        msg = _action_messages.get(action, f"[SIMULATED] Action '{action}' executed with params {params}")
        logger.info("Playbook step [%s] %s: %s", incident_id, step.name, msg)
        return msg
