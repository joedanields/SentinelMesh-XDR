"""Incident Responder Agent – generates prioritised response playbooks."""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

import structlog

from .base_agent import AgentResult, BaseAgent

logger = structlog.get_logger(__name__)

SYSTEM_PROMPT = """You are an expert incident response specialist integrated into SentinelMesh XDR.

Generate a detailed, actionable incident response playbook for the security event provided.

Return ONLY this exact JSON structure (no prose outside JSON):
{
  "playbook_id": "<uuid string>",
  "playbook_name": "<short human-readable name>",
  "immediate_actions": [
    {"priority": <1-5>, "action": "<action>", "responsible": "<SOC|SRE|Management>", "automated": <bool>}
  ],
  "short_term_actions": [
    {"action": "<action>", "timeframe": "<within Xh>", "responsible": "<role>"}
  ],
  "long_term_actions": [
    {"action": "<action>", "timeframe": "<within Xd/Xw>", "responsible": "<role>"}
  ],
  "containment": {
    "steps": ["<step1>", ...],
    "block_ips": ["<ip1>", ...],
    "isolate_hosts": ["<host1>", ...],
    "disable_accounts": ["<user1>", ...]
  },
  "eradication": {
    "steps": ["<step1>", ...],
    "artifacts_to_remove": ["<artifact1>", ...]
  },
  "recovery": {
    "steps": ["<step1>", ...],
    "restore_order": ["<step1>", ...]
  },
  "ioc_queries": [
    {"description": "<what to hunt for>", "query": "<SIEM/KQL query>", "platform": "<elastic|splunk|generic>"}
  ],
  "impact_assessment": {
    "affected_systems": ["<system1>", ...],
    "data_at_risk": "<description>",
    "blast_radius": "<low|medium|high|critical>",
    "business_impact": "<description>",
    "estimated_recovery_hours": <int>
  },
  "confidence": <float 0.0-1.0>
}

Rules:
- immediate_actions must be ordered by priority (1=highest)
- Include at least 3 immediate actions, 2 short-term, 2 long-term
- ioc_queries must contain at least 2 hunting queries
- blast_radius based on severity and scope of the event
"""

# Canned playbooks used as both prompt context and rule-based fallback
PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "brute_force": {
        "playbook_name": "Brute Force Response",
        "immediate_actions": [
            {"priority": 1, "action": "Temporarily block source IP at perimeter firewall", "responsible": "SOC", "automated": True},
            {"priority": 2, "action": "Lock targeted user account(s)", "responsible": "SOC", "automated": True},
            {"priority": 3, "action": "Alert account owner and require MFA re-enrollment", "responsible": "SOC", "automated": False},
        ],
        "short_term_actions": [
            {"action": "Enable adaptive MFA for all affected accounts", "timeframe": "within 2h", "responsible": "SRE"},
            {"action": "Review auth logs for successful logins from the same source", "timeframe": "within 4h", "responsible": "SOC"},
        ],
        "long_term_actions": [
            {"action": "Implement account lockout policy after N failures", "timeframe": "within 1w", "responsible": "SRE"},
            {"action": "Deploy CAPTCHA on public-facing login pages", "timeframe": "within 2w", "responsible": "SRE"},
        ],
        "containment": {"steps": ["Block attacking IP", "Lock accounts"], "block_ips": [], "isolate_hosts": [], "disable_accounts": []},
        "eradication": {"steps": ["Remove unauthorised sessions", "Rotate credentials"], "artifacts_to_remove": []},
        "recovery": {"steps": ["Re-enable accounts after password reset", "Monitor closely for 24h"], "restore_order": []},
        "ioc_queries": [
            {"description": "Failed logins from attacking IP", "query": "event.action:authentication_failed AND source.ip:<ATTACKER_IP>", "platform": "elastic"},
            {"description": "Successful logins after brute-force period", "query": "event.action:authentication_success AND source.ip:<ATTACKER_IP>", "platform": "elastic"},
        ],
        "impact_assessment": {"affected_systems": [], "data_at_risk": "User credentials", "blast_radius": "medium", "business_impact": "Potential account compromise", "estimated_recovery_hours": 4},
    },
    "ransomware": {
        "playbook_name": "Ransomware Kill Chain Response",
        "immediate_actions": [
            {"priority": 1, "action": "IMMEDIATELY isolate all affected hosts from the network", "responsible": "SOC", "automated": True},
            {"priority": 2, "action": "Snapshot affected VMs / suspend cloud instances", "responsible": "SRE", "automated": True},
            {"priority": 3, "action": "Alert management and initiate business continuity plan", "responsible": "Management", "automated": False},
            {"priority": 4, "action": "Preserve forensic images before any remediation", "responsible": "SOC", "automated": False},
            {"priority": 5, "action": "Block C2 domains and IPs at DNS and firewall", "responsible": "SOC", "automated": True},
        ],
        "short_term_actions": [
            {"action": "Identify patient-zero host and initial infection vector", "timeframe": "within 1h", "responsible": "SOC"},
            {"action": "Check backup integrity and last-known-good state", "timeframe": "within 2h", "responsible": "SRE"},
        ],
        "long_term_actions": [
            {"action": "Deploy endpoint detection and response (EDR) on all hosts", "timeframe": "within 1w", "responsible": "SRE"},
            {"action": "Implement offline / immutable backup strategy", "timeframe": "within 2w", "responsible": "SRE"},
        ],
        "containment": {"steps": ["Isolate hosts", "Block C2", "Revoke credentials"], "block_ips": [], "isolate_hosts": [], "disable_accounts": []},
        "eradication": {"steps": ["Remove ransomware binaries", "Patch exploited vulnerability", "Clean persistence mechanisms"], "artifacts_to_remove": ["*.locked files (metadata only)", "Scheduled tasks", "Registry run keys"]},
        "recovery": {"steps": ["Restore from clean backups", "Rebuild affected systems", "Verify integrity before reconnecting"], "restore_order": ["Core services first", "then user workstations"]},
        "ioc_queries": [
            {"description": "File encryption activity", "query": "file.extension:(locked OR crypt OR encrypted) AND event.action:file_rename", "platform": "elastic"},
            {"description": "Ransomware note drops", "query": "file.name:(README_DECRYPT* OR HOW_TO_DECRYPT* OR RECOVER_FILES*)", "platform": "elastic"},
        ],
        "impact_assessment": {"affected_systems": [], "data_at_risk": "All encrypted files on affected hosts", "blast_radius": "critical", "business_impact": "Full operational disruption possible", "estimated_recovery_hours": 72},
    },
    "data_exfiltration": {
        "playbook_name": "Data Exfiltration Response",
        "immediate_actions": [
            {"priority": 1, "action": "Block outbound connections from exfiltrating host(s)", "responsible": "SOC", "automated": True},
            {"priority": 2, "action": "Identify and classify data being exfiltrated", "responsible": "SOC", "automated": False},
            {"priority": 3, "action": "Notify Data Protection Officer and Legal", "responsible": "Management", "automated": False},
        ],
        "short_term_actions": [
            {"action": "Enumerate all outbound data transfers in last 24h", "timeframe": "within 2h", "responsible": "SOC"},
            {"action": "Determine if data subject notification is required (GDPR/CCPA)", "timeframe": "within 24h", "responsible": "Management"},
        ],
        "long_term_actions": [
            {"action": "Deploy DLP solution", "timeframe": "within 2w", "responsible": "SRE"},
            {"action": "Implement egress filtering and data classification", "timeframe": "within 1m", "responsible": "SRE"},
        ],
        "containment": {"steps": ["Block destination IPs/domains", "Terminate active sessions"], "block_ips": [], "isolate_hosts": [], "disable_accounts": []},
        "eradication": {"steps": ["Remove exfiltration tools", "Revoke compromised credentials"], "artifacts_to_remove": []},
        "recovery": {"steps": ["Monitor for repeat attempts", "Re-evaluate data access controls"], "restore_order": []},
        "ioc_queries": [
            {"description": "Large outbound transfers", "query": "network.bytes > 10000000 AND network.direction:outbound", "platform": "elastic"},
            {"description": "Data staged for exfiltration", "query": "process.name:(zip OR 7z OR rar OR tar) AND file.path:/sensitive/", "platform": "elastic"},
        ],
        "impact_assessment": {"affected_systems": [], "data_at_risk": "Sensitive/regulated data", "blast_radius": "high", "business_impact": "Regulatory penalties and reputational damage", "estimated_recovery_hours": 48},
    },
    "lateral_movement": {
        "playbook_name": "Lateral Movement Response",
        "immediate_actions": [
            {"priority": 1, "action": "Isolate identified pivot hosts", "responsible": "SOC", "automated": True},
            {"priority": 2, "action": "Reset credentials for accounts used in lateral movement", "responsible": "SOC", "automated": False},
            {"priority": 3, "action": "Review and revoke unnecessary SMB/RDP/SSH access", "responsible": "SRE", "automated": False},
        ],
        "short_term_actions": [
            {"action": "Map full attack path using network flow data", "timeframe": "within 4h", "responsible": "SOC"},
            {"action": "Scan all internal hosts for compromise indicators", "timeframe": "within 8h", "responsible": "SOC"},
        ],
        "long_term_actions": [
            {"action": "Implement network segmentation / micro-segmentation", "timeframe": "within 2w", "responsible": "SRE"},
            {"action": "Deploy privileged access management (PAM) solution", "timeframe": "within 1m", "responsible": "SRE"},
        ],
        "containment": {"steps": ["Isolate pivot hosts", "Block lateral protocols"], "block_ips": [], "isolate_hosts": [], "disable_accounts": []},
        "eradication": {"steps": ["Remove tools dropped by attacker", "Clean persistence"], "artifacts_to_remove": []},
        "recovery": {"steps": ["Verify clean state before reconnecting hosts", "Monitor east-west traffic"], "restore_order": []},
        "ioc_queries": [
            {"description": "Pass-the-hash activity", "query": "event.action:logon AND winlog.event_data.LogonType:3 AND source.ip:internal", "platform": "elastic"},
            {"description": "PsExec / remote execution", "query": "process.name:(psexec* OR wmic*) OR winlog.event_id:7045", "platform": "elastic"},
        ],
        "impact_assessment": {"affected_systems": [], "data_at_risk": "All systems reachable from pivot host", "blast_radius": "high", "business_impact": "Potential full domain compromise", "estimated_recovery_hours": 24},
    },
    "phishing": {
        "playbook_name": "Phishing Response",
        "immediate_actions": [
            {"priority": 1, "action": "Block sender domain and IP at email gateway", "responsible": "SOC", "automated": True},
            {"priority": 2, "action": "Purge phishing emails from all mailboxes", "responsible": "SOC", "automated": True},
            {"priority": 3, "action": "Notify affected users and require credential rotation", "responsible": "SOC", "automated": False},
        ],
        "short_term_actions": [
            {"action": "Identify all users who clicked phishing links", "timeframe": "within 2h", "responsible": "SOC"},
            {"action": "Block phishing URLs at web proxy", "timeframe": "within 1h", "responsible": "SOC"},
        ],
        "long_term_actions": [
            {"action": "Conduct mandatory phishing awareness training", "timeframe": "within 1w", "responsible": "Management"},
            {"action": "Enable DMARC/DKIM/SPF enforcement", "timeframe": "within 2w", "responsible": "SRE"},
        ],
        "containment": {"steps": ["Block sender", "Purge emails", "Reset credentials"], "block_ips": [], "isolate_hosts": [], "disable_accounts": []},
        "eradication": {"steps": ["Remove malicious email artifacts", "Scan attachments"], "artifacts_to_remove": []},
        "recovery": {"steps": ["Monitor for follow-on access from compromised accounts"], "restore_order": []},
        "ioc_queries": [
            {"description": "Clicks on phishing URLs", "query": "url.domain:<PHISHING_DOMAIN> AND event.action:url_request", "platform": "elastic"},
            {"description": "Credential harvesting submissions", "query": "http.request.method:POST AND url.path:/login AND url.domain:<PHISHING_DOMAIN>", "platform": "elastic"},
        ],
        "impact_assessment": {"affected_systems": ["Email infrastructure"], "data_at_risk": "User credentials", "blast_radius": "medium", "business_impact": "Account compromise and further intrusion", "estimated_recovery_hours": 8},
    },
}


class IncidentResponderAgent(BaseAgent):
    """Generate actionable incident response playbooks for detected threats."""

    REQUIRED_KEYS = [
        "playbook_id", "immediate_actions", "containment", "eradication", "recovery",
        "ioc_queries", "impact_assessment"
    ]

    def __init__(self, model_name: str = "llama3") -> None:
        super().__init__(
            name="IncidentResponderAgent",
            description="Generates incident response playbooks and remediation guidance.",
            model_name=model_name,
        )

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def build_prompt(self, input_data: Any) -> tuple[str, str]:
        if isinstance(input_data, dict):
            category = input_data.get("category", "unknown")
            severity = input_data.get("severity", 5)
            indicators = input_data.get("indicators", [])
            description = input_data.get("description", "")
            entities = input_data.get("entities", {})

            playbook_hint = ""
            if category in PLAYBOOKS:
                playbook_hint = f"\n\nReference playbook available for {category}. Customise it for this specific incident."

            user_prompt = (
                f"Generate an incident response playbook for this threat:\n\n"
                f"Category: {category}\n"
                f"Severity: {severity}/10\n"
                f"Description: {description}\n"
                f"Indicators: {indicators}\n"
                f"Affected entities: {entities}"
                f"{playbook_hint}"
            )
        else:
            user_prompt = f"Generate an incident response playbook for:\n\n{input_data}"

        return SYSTEM_PROMPT, user_prompt

    def parse_response(self, raw_text: str) -> Dict[str, Any]:
        parsed = self._extract_json(raw_text)
        if not parsed:
            return {}

        if not parsed.get("playbook_id"):
            parsed["playbook_id"] = str(uuid.uuid4())

        for key in ("immediate_actions", "short_term_actions", "long_term_actions", "ioc_queries"):
            if key not in parsed:
                parsed[key] = []

        for nested in ("containment", "eradication", "recovery", "impact_assessment"):
            if nested not in parsed:
                parsed[nested] = {}

        return parsed

    async def analyze(self, input_data: Any) -> AgentResult:
        return await self._run_analysis(
            input_data,
            required_keys=self.REQUIRED_KEYS,
            fallback_fn=self._canned_playbook_fallback,
        )

    # ------------------------------------------------------------------
    # Canned-playbook fallback
    # ------------------------------------------------------------------

    def _canned_playbook_fallback(self, input_data: Any) -> Dict[str, Any]:
        category = "unknown"
        if isinstance(input_data, dict):
            category = input_data.get("category", "unknown")

        playbook = PLAYBOOKS.get(category, PLAYBOOKS.get("brute_force", {}))
        result = dict(playbook)
        result["playbook_id"] = str(uuid.uuid4())
        result["confidence"] = 0.4

        # Inject known entities into containment blocks
        if isinstance(input_data, dict):
            entities = input_data.get("entities", {})
            containment = dict(result.get("containment", {}))
            containment["block_ips"] = list(set(entities.get("ips", []) + containment.get("block_ips", [])))
            containment["isolate_hosts"] = list(set(entities.get("hosts", []) + containment.get("isolate_hosts", [])))
            containment["disable_accounts"] = list(set(entities.get("users", []) + containment.get("disable_accounts", [])))
            result["containment"] = containment

        return result
