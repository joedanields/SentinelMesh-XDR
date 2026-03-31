"""Threat Classifier Agent – classifies detected threats with MITRE ATT&CK mapping."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import structlog

from .base_agent import AgentResult, BaseAgent

logger = structlog.get_logger(__name__)

SYSTEM_PROMPT = """You are an expert threat classification engine for SentinelMesh XDR.

Your role is to classify security threats and map them to MITRE ATT&CK framework.

Supported threat categories (pick the best match):
1.  brute_force            – Repeated login/auth failures targeting credentials
2.  credential_stuffing    – Using leaked credential lists against services
3.  sql_injection          – SQL code injected into application inputs
4.  command_injection      – OS commands injected via application input
5.  xss                    – Cross-site scripting attempts
6.  path_traversal         – Directory traversal / path manipulation
7.  data_exfiltration      – Unauthorised data being sent out of the network
8.  lateral_movement       – Attacker moving between internal systems
9.  privilege_escalation   – Gaining higher permissions than authorised
10. ransomware             – File encryption / ransom-demanding behaviour
11. malware_execution      – Known-bad or suspicious process execution
12. phishing               – Social-engineering email or web-based deception
13. recon_scanning         – Port/service/vulnerability scanning activity
14. c2_communication       – Command-and-control beacon or callback traffic
15. insider_threat         – Malicious or negligent authorised-user behaviour
16. supply_chain_attack    – Compromise via trusted vendor/software channel
17. denial_of_service      – Resource exhaustion attack
18. dns_tunnelling         – Data exfil or C2 via DNS protocol
19. web_shell              – Remote shell installed via web server exploit
20. persistence_mechanism  – Scheduled tasks, registry run keys, startup items
21. credential_dumping     – Extracting credentials from memory or files
22. unknown                – Does not fit the above categories

Attack stages (MITRE killchain):
reconnaissance | initial_access | execution | persistence | privilege_escalation |
defense_evasion | credential_access | discovery | lateral_movement | collection |
command_and_control | exfiltration | impact

Return ONLY this JSON (no prose):
{
  "category": "<one of the 22 categories above>",
  "severity": <integer 1-10>,
  "confidence": <float 0.0-1.0>,
  "mitre_mapping": {
    "tactic": "<tactic name>",
    "technique_id": "<T####>",
    "technique_name": "<name>",
    "sub_technique_id": "<T####.###  or null>"
  },
  "attack_stage": "<stage from list above>",
  "threat_actor_profile": {
    "sophistication": "<low|medium|high|nation_state>",
    "motivation": "<financial|espionage|disruption|hacktivism|unknown>",
    "likely_group": "<APT name or null>"
  },
  "indicators": ["<ioc1>", ...],
  "description": "<1-sentence description of this specific threat instance>"
}
"""

# Simple keyword-based fallback rules
CATEGORY_RULES: List[tuple[str, str, int]] = [
    (r"brute.?force|password.?spray|auth.?fail", "brute_force", 6),
    (r"sql.?inject|' OR |UNION SELECT", "sql_injection", 7),
    (r"cmd.?inject|;\s*ls|;\s*cat|;\s*whoami", "command_injection", 8),
    (r"exfiltrat|data.?theft|upload.*sensitive", "data_exfiltration", 9),
    (r"lateral.?move|pass.?the.?hash|wmi|psexec", "lateral_movement", 8),
    (r"escalat|sudo|setuid|privilege", "privilege_escalation", 7),
    (r"ransom|encrypt.*files|\.locked|\.crypt", "ransomware", 10),
    (r"malware|trojan|backdoor|rootkit", "malware_execution", 8),
    (r"phish|spear.?phish|credential.?harvest", "phishing", 6),
    (r"port.?scan|nmap|masscan|recon", "recon_scanning", 4),
    (r"beacon|c2|command.?control|call.?home", "c2_communication", 8),
    (r"dns.?tunnel|iodine|dnscat", "dns_tunnelling", 7),
    (r"web.?shell|webshell|cmd\.php|shell\.aspx", "web_shell", 9),
    (r"mimikatz|lsass|credential.?dump|hashdump", "credential_dumping", 9),
    (r"persist|startup|crontab|registry.*run", "persistence_mechanism", 6),
]

MITRE_MAP: Dict[str, Dict[str, str]] = {
    "brute_force": {"tactic": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force", "sub_technique_id": None},
    "credential_stuffing": {"tactic": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force", "sub_technique_id": "T1110.004"},
    "sql_injection": {"tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "sub_technique_id": None},
    "command_injection": {"tactic": "Execution", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "sub_technique_id": None},
    "xss": {"tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "sub_technique_id": None},
    "path_traversal": {"tactic": "Discovery", "technique_id": "T1083", "technique_name": "File and Directory Discovery", "sub_technique_id": None},
    "data_exfiltration": {"tactic": "Exfiltration", "technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel", "sub_technique_id": None},
    "lateral_movement": {"tactic": "Lateral Movement", "technique_id": "T1021", "technique_name": "Remote Services", "sub_technique_id": None},
    "privilege_escalation": {"tactic": "Privilege Escalation", "technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation", "sub_technique_id": None},
    "ransomware": {"tactic": "Impact", "technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "sub_technique_id": None},
    "malware_execution": {"tactic": "Execution", "technique_id": "T1204", "technique_name": "User Execution", "sub_technique_id": None},
    "phishing": {"tactic": "Initial Access", "technique_id": "T1566", "technique_name": "Phishing", "sub_technique_id": None},
    "recon_scanning": {"tactic": "Reconnaissance", "technique_id": "T1595", "technique_name": "Active Scanning", "sub_technique_id": None},
    "c2_communication": {"tactic": "Command and Control", "technique_id": "T1071", "technique_name": "Application Layer Protocol", "sub_technique_id": None},
    "insider_threat": {"tactic": "Collection", "technique_id": "T1530", "technique_name": "Data from Cloud Storage", "sub_technique_id": None},
    "supply_chain_attack": {"tactic": "Initial Access", "technique_id": "T1195", "technique_name": "Supply Chain Compromise", "sub_technique_id": None},
    "denial_of_service": {"tactic": "Impact", "technique_id": "T1498", "technique_name": "Network Denial of Service", "sub_technique_id": None},
    "dns_tunnelling": {"tactic": "Exfiltration", "technique_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol", "sub_technique_id": "T1048.003"},
    "web_shell": {"tactic": "Persistence", "technique_id": "T1505", "technique_name": "Server Software Component", "sub_technique_id": "T1505.003"},
    "persistence_mechanism": {"tactic": "Persistence", "technique_id": "T1053", "technique_name": "Scheduled Task/Job", "sub_technique_id": None},
    "credential_dumping": {"tactic": "Credential Access", "technique_id": "T1003", "technique_name": "OS Credential Dumping", "sub_technique_id": None},
    "unknown": {"tactic": "Unknown", "technique_id": "T0000", "technique_name": "Unknown", "sub_technique_id": None},
}


class ThreatClassifierAgent(BaseAgent):
    """Classify security threats and map them to MITRE ATT&CK."""

    REQUIRED_KEYS = [
        "category", "severity", "confidence", "mitre_mapping", "attack_stage", "indicators"
    ]

    def __init__(self, model_name: str = "llama3") -> None:
        super().__init__(
            name="ThreatClassifierAgent",
            description="Classifies threats and maps them to MITRE ATT&CK.",
            model_name=model_name,
        )

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def build_prompt(self, input_data: Any) -> tuple[str, str]:
        if isinstance(input_data, dict):
            content = (
                f"Alert/Event data:\n{input_data.get('description', '')}\n"
                f"Raw log: {input_data.get('raw_log', '')}\n"
                f"Tags: {input_data.get('tags', [])}\n"
                f"Source: {input_data.get('source', 'unknown')}"
            )
        else:
            content = str(input_data)

        user_prompt = f"Classify this security event and map to MITRE ATT&CK:\n\n{content}"
        return SYSTEM_PROMPT, user_prompt

    def parse_response(self, raw_text: str) -> Dict[str, Any]:
        parsed = self._extract_json(raw_text)
        if not parsed:
            return {}

        # Ensure required nested keys
        parsed.setdefault("mitre_mapping", {})
        parsed.setdefault("threat_actor_profile", {})
        parsed.setdefault("indicators", [])

        # Clamp severity
        try:
            parsed["severity"] = max(1, min(10, int(parsed.get("severity", 5))))
        except (TypeError, ValueError):
            parsed["severity"] = 5

        return parsed

    async def analyze(self, input_data: Any) -> AgentResult:
        return await self._run_analysis(
            input_data,
            required_keys=self.REQUIRED_KEYS,
            fallback_fn=self._rule_based_fallback,
        )

    # ------------------------------------------------------------------
    # Rule-based fallback
    # ------------------------------------------------------------------

    def _rule_based_fallback(self, input_data: Any) -> Dict[str, Any]:
        text = (
            str(input_data.get("raw_log", "")) + " " + str(input_data.get("description", ""))
            if isinstance(input_data, dict)
            else str(input_data)
        )

        category = "unknown"
        severity = 5

        for pattern, cat, sev in CATEGORY_RULES:
            if re.search(pattern, text, re.I):
                category = cat
                severity = sev
                break

        mitre = MITRE_MAP.get(category, MITRE_MAP["unknown"])

        return {
            "category": category,
            "severity": severity,
            "confidence": 0.4,
            "mitre_mapping": mitre,
            "attack_stage": "unknown",
            "threat_actor_profile": {
                "sophistication": "unknown",
                "motivation": "unknown",
                "likely_group": None,
            },
            "indicators": [],
            "description": f"Rule-based classification: {category}",
        }
