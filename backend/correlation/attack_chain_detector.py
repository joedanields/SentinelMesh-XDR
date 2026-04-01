"""Attack Chain Detector – matches event sequences to known kill-chain patterns."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)

PARTIAL_MATCH_THRESHOLD = 0.5   # ≥50% of chain steps matched → alert
CHAIN_TIME_WINDOW = timedelta(hours=24)


@dataclass
class ChainStep:
    """One step in an attack chain pattern."""

    name: str
    event_types: List[str]     # event_type values that satisfy this step
    keywords: List[str]        # raw_log keywords (any match satisfies)
    required: bool = True      # if False, the step is optional


@dataclass
class AttackChainPattern:
    """A named multi-step attack sequence."""

    pattern_id: str
    name: str
    description: str
    steps: List[ChainStep]
    severity: str              # low|medium|high|critical
    mitre_tactic: str
    tags: List[str] = field(default_factory=list)


@dataclass
class ChainMatch:
    """Result of matching events against an attack chain pattern."""

    match_id: str
    pattern_id: str
    pattern_name: str
    matched_steps: List[str]
    unmatched_steps: List[str]
    match_ratio: float         # matched / total required
    confidence: float
    matched_event_ids: List[str]
    severity: str
    is_partial: bool
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "match_id": self.match_id,
            "pattern_id": self.pattern_id,
            "pattern_name": self.pattern_name,
            "matched_steps": self.matched_steps,
            "unmatched_steps": self.unmatched_steps,
            "match_ratio": round(self.match_ratio, 3),
            "confidence": round(self.confidence, 3),
            "matched_event_ids": self.matched_event_ids,
            "severity": self.severity,
            "is_partial": self.is_partial,
            "description": self.description,
        }


# ---------------------------------------------------------------------------
# Built-in Attack Chain Patterns
# ---------------------------------------------------------------------------

BUILTIN_PATTERNS: List[AttackChainPattern] = [
    AttackChainPattern(
        pattern_id="ACP001",
        name="Brute Force to Access",
        description="Attacker brute-forces credentials, gains access, escalates privileges.",
        steps=[
            ChainStep("recon", ["recon_scanning", "discovery"], ["nmap", "scan", "enum"]),
            ChainStep("brute_force", ["auth_failure", "brute_force"], ["failed", "invalid", "password_spray"]),
            ChainStep("access_gained", ["auth_success", "login"], ["authenticated", "success", "session_opened"]),
            ChainStep("privilege_escalation", ["privilege_escalation", "sudo"], ["sudo", "su ", "admin", "elevated"]),
        ],
        severity="high",
        mitre_tactic="Initial Access → Privilege Escalation",
        tags=["brute_force", "initial_access"],
    ),
    AttackChainPattern(
        pattern_id="ACP002",
        name="Scan-Exploit-Persist",
        description="Network scan, vulnerability exploitation, followed by persistence.",
        steps=[
            ChainStep("network_scan", ["recon_scanning", "port_scan"], ["nmap", "masscan", "scan"]),
            ChainStep("exploit", ["exploit", "vulnerability"], ["exploit", "CVE", "buffer_overflow", "RCE"]),
            ChainStep("execution", ["execution", "command_injection"], ["cmd", "shell", "exec", "whoami"]),
            ChainStep("persistence", ["persistence_mechanism", "cron"], ["crontab", "startup", "registry", "service_install"]),
        ],
        severity="critical",
        mitre_tactic="Initial Access → Execution → Persistence",
        tags=["exploit", "persistence"],
    ),
    AttackChainPattern(
        pattern_id="ACP003",
        name="Phishing to Lateral Movement",
        description="Phishing email leads to credential compromise and lateral movement.",
        steps=[
            ChainStep("phishing_received", ["email", "phishing"], ["phish", "attachment", "malicious_url"]),
            ChainStep("initial_access", ["auth_success", "execution"], ["credential", "access", "login"]),
            ChainStep("lateral_movement", ["lateral_movement", "remote_service"], ["psexec", "wmi", "rdp", "smb", "lateral"]),
            ChainStep("data_collection", ["collection", "file_access"], ["staged", "archive", "compress", "xcopy"]),
        ],
        severity="high",
        mitre_tactic="Initial Access → Lateral Movement → Collection",
        tags=["phishing", "lateral_movement"],
    ),
    AttackChainPattern(
        pattern_id="ACP004",
        name="Ransomware Kill Chain",
        description="Full ransomware attack from initial access to encryption.",
        steps=[
            ChainStep("initial_access", ["auth_success", "execution", "phishing"], ["phish", "exploit", "macros"]),
            ChainStep("recon_internal", ["discovery", "recon_scanning"], ["net view", "ipconfig", "whoami", "domain_enum"]),
            ChainStep("lateral_movement", ["lateral_movement"], ["psexec", "wmi", "lateral"]),
            ChainStep("disable_defenses", ["defense_evasion"], ["av_disabled", "defender", "wdav"]),
            ChainStep("encryption", ["ransomware", "file_modification"], ["encrypt", ".locked", ".crypt", "readme_decrypt"]),
        ],
        severity="critical",
        mitre_tactic="Initial Access → Execution → Impact",
        tags=["ransomware"],
    ),
    AttackChainPattern(
        pattern_id="ACP005",
        name="Data Theft Campaign",
        description="Attacker stages and exfiltrates sensitive data.",
        steps=[
            ChainStep("initial_access", ["auth_success", "initial_access"], ["login", "session"]),
            ChainStep("discovery", ["discovery", "file_access"], ["ls", "dir", "find", "locate"]),
            ChainStep("collection", ["collection", "file_access"], ["copy", "zip", "tar", "archive"]),
            ChainStep("exfiltration", ["data_exfiltration", "network"], ["upload", "ftp", "scp", "http_post", "exfil"]),
        ],
        severity="high",
        mitre_tactic="Discovery → Collection → Exfiltration",
        tags=["data_exfiltration"],
    ),
    AttackChainPattern(
        pattern_id="ACP006",
        name="APT Lateral Movement",
        description="Advanced persistent threat moving laterally with credential reuse.",
        steps=[
            ChainStep("credential_dumping", ["credential_dumping"], ["mimikatz", "lsass", "hashdump", "sekurlsa"]),
            ChainStep("lateral_movement_1", ["lateral_movement"], ["pass_the_hash", "pass_the_ticket", "overpass"]),
            ChainStep("remote_execution", ["execution", "remote_service"], ["psexec", "wmi", "winrm", "remote_shell"]),
            ChainStep("lateral_movement_2", ["lateral_movement"], ["smb", "rdp", "ssh"]),
            ChainStep("persistence", ["persistence_mechanism"], ["registry", "service", "scheduled_task"]),
        ],
        severity="critical",
        mitre_tactic="Credential Access → Lateral Movement → Persistence",
        tags=["apt", "lateral_movement", "credential_dumping"],
    ),
    AttackChainPattern(
        pattern_id="ACP007",
        name="Web Application Attack",
        description="Web exploitation chain: recon, injection, web shell, lateral.",
        steps=[
            ChainStep("web_recon", ["recon_scanning", "http"], ["dirb", "nikto", "gobuster", "spider"]),
            ChainStep("injection", ["sql_injection", "command_injection", "xss"], ["union", "sleep(", "exec(", "alert("]),
            ChainStep("web_shell", ["web_shell", "execution"], ["webshell", "cmd.php", "shell.aspx", "c99"]),
            ChainStep("pivoting", ["lateral_movement", "network"], ["curl", "wget", "netcat", "pivot"]),
        ],
        severity="high",
        mitre_tactic="Initial Access → Execution → Lateral Movement",
        tags=["web_attack", "injection"],
    ),
    AttackChainPattern(
        pattern_id="ACP008",
        name="DNS Tunnelling C2",
        description="Malware uses DNS for command-and-control communications.",
        steps=[
            ChainStep("malware_exec", ["malware_execution", "execution"], ["malware", "trojan", "dropper"]),
            ChainStep("dns_c2_setup", ["dns_tunnelling", "dns"], ["dnscat", "iodine", "dns_query_large"]),
            ChainStep("c2_comm", ["c2_communication"], ["beacon", "heartbeat", "c2", "callback"]),
            ChainStep("exfil_via_dns", ["data_exfiltration", "dns_tunnelling"], ["dns_exfil", "txt_record_large"]),
        ],
        severity="high",
        mitre_tactic="Execution → Command and Control → Exfiltration",
        tags=["c2", "dns_tunnelling"],
    ),
    AttackChainPattern(
        pattern_id="ACP009",
        name="Insider Data Theft",
        description="Trusted insider accesses and exfiltrates sensitive data.",
        steps=[
            ChainStep("off_hours_login", ["auth_success", "login"], ["weekend", "night", "off_hours"]),
            ChainStep("bulk_file_access", ["file_access", "collection"], ["bulk_download", "mass_copy", "large_download"]),
            ChainStep("cloud_upload", ["data_exfiltration"], ["dropbox", "gdrive", "onedrive", "s3", "upload"]),
        ],
        severity="high",
        mitre_tactic="Collection → Exfiltration",
        tags=["insider_threat", "data_exfiltration"],
    ),
    AttackChainPattern(
        pattern_id="ACP010",
        name="Supply Chain Compromise",
        description="Malicious code injected via trusted software supply chain.",
        steps=[
            ChainStep("software_update", ["software_update", "execution"], ["update", "patch", "installer", "package"]),
            ChainStep("malicious_exec", ["malware_execution", "execution"], ["svchost", "rundll32", "powershell", "wscript"]),
            ChainStep("c2_beacon", ["c2_communication"], ["beacon", "callback", "c2"]),
            ChainStep("credential_harvest", ["credential_dumping", "credential_access"], ["credentials", "token", "api_key"]),
        ],
        severity="critical",
        mitre_tactic="Initial Access → Execution → Credential Access",
        tags=["supply_chain"],
    ),
    AttackChainPattern(
        pattern_id="ACP011",
        name="Cloud Account Takeover",
        description="Cloud credentials compromised, then abused for resource access.",
        steps=[
            ChainStep("credential_phish", ["phishing", "auth_failure"], ["phish", "mfa_push", "token_theft"]),
            ChainStep("cloud_login", ["auth_success"], ["cloud", "aws", "azure", "gcp", "console_login"]),
            ChainStep("enumeration", ["discovery"], ["list_buckets", "list_instances", "describe_"]),
            ChainStep("resource_abuse", ["execution", "data_exfiltration"], ["launch_instance", "create_user", "get_object"]),
        ],
        severity="high",
        mitre_tactic="Initial Access → Discovery → Collection",
        tags=["cloud", "account_takeover"],
    ),
    AttackChainPattern(
        pattern_id="ACP012",
        name="Credential Stuffing to Account Fraud",
        description="Credential stuffing leads to account access and financial fraud.",
        steps=[
            ChainStep("stuffing_attempt", ["brute_force", "auth_failure"], ["credential_stuff", "password_spray", "401", "403"]),
            ChainStep("successful_login", ["auth_success"], ["200", "authenticated", "session_created"]),
            ChainStep("account_manipulation", ["account_modification"], ["change_email", "change_phone", "add_payment"]),
        ],
        severity="high",
        mitre_tactic="Initial Access → Credential Access",
        tags=["credential_stuffing", "fraud"],
    ),
]


class AttackChainDetector:
    """
    Matches sequences of security events against known attack chain patterns.

    Uses a sliding-window approach to detect both full and partial chain matches.
    """

    def __init__(
        self,
        patterns: Optional[List[AttackChainPattern]] = None,
        partial_threshold: float = PARTIAL_MATCH_THRESHOLD,
        time_window: timedelta = CHAIN_TIME_WINDOW,
    ) -> None:
        self.patterns = patterns or BUILTIN_PATTERNS
        self.partial_threshold = partial_threshold
        self.time_window = time_window
        self._log = logger.bind(component="AttackChainDetector")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, events: List[Dict[str, Any]]) -> List[ChainMatch]:
        """
        Check events against all patterns. Returns a list of ChainMatch objects
        (both full and partial matches above the threshold).
        """
        if not events:
            return []

        self._log.info("chain_detection_start", event_count=len(events), patterns=len(self.patterns))
        matches: List[ChainMatch] = []

        for pattern in self.patterns:
            match = self._match_pattern(pattern, events)
            if match:
                matches.append(match)

        matches.sort(key=lambda m: m.match_ratio, reverse=True)
        self._log.info("chain_detection_complete", matches=len(matches))
        return matches

    def detect_single(self, pattern_id: str, events: List[Dict[str, Any]]) -> Optional[ChainMatch]:
        """Run detection for a specific pattern only."""
        pattern = next((p for p in self.patterns if p.pattern_id == pattern_id), None)
        if not pattern:
            return None
        return self._match_pattern(pattern, events)

    def add_pattern(self, pattern: AttackChainPattern) -> None:
        self.patterns.append(pattern)

    def list_patterns(self) -> List[Dict[str, Any]]:
        return [
            {
                "pattern_id": p.pattern_id,
                "name": p.name,
                "description": p.description,
                "step_count": len(p.steps),
                "severity": p.severity,
                "tags": p.tags,
            }
            for p in self.patterns
        ]

    # ------------------------------------------------------------------
    # Pattern matching engine
    # ------------------------------------------------------------------

    def _match_pattern(
        self, pattern: AttackChainPattern, events: List[Dict[str, Any]]
    ) -> Optional[ChainMatch]:
        """
        Try to match the pattern against the event list using a sliding window.
        Returns a ChainMatch if at least `partial_threshold` of required steps matched.
        """
        required_steps = [s for s in pattern.steps if s.required]
        if not required_steps:
            return None

        matched_steps: List[str] = []
        matched_event_ids: List[str] = []
        unmatched: List[str] = []
        search_start = 0

        for step in pattern.steps:
            step_matched = False
            for idx in range(search_start, len(events)):
                event = events[idx]
                if self._event_satisfies_step(event, step):
                    matched_steps.append(step.name)
                    eid = event.get("id", str(uuid.uuid4()))
                    matched_event_ids.append(eid)
                    search_start = idx + 1
                    step_matched = True
                    break

            if not step_matched:
                if step.required:
                    unmatched.append(step.name)

        required_matched = sum(1 for s in matched_steps if s in {st.name for st in required_steps})
        match_ratio = required_matched / len(required_steps)

        if match_ratio < self.partial_threshold:
            return None

        is_partial = match_ratio < 1.0
        confidence = self._chain_confidence(match_ratio, len(matched_event_ids), len(events))

        return ChainMatch(
            match_id=str(uuid.uuid4()),
            pattern_id=pattern.pattern_id,
            pattern_name=pattern.name,
            matched_steps=matched_steps,
            unmatched_steps=unmatched,
            match_ratio=match_ratio,
            confidence=confidence,
            matched_event_ids=matched_event_ids,
            severity=pattern.severity,
            is_partial=is_partial,
            description=(
                f"{'Partial' if is_partial else 'Full'} match: {pattern.name}. "
                f"Matched {required_matched}/{len(required_steps)} required steps."
            ),
        )

    def _event_satisfies_step(self, event: Dict[str, Any], step: ChainStep) -> bool:
        """Return True if the event matches the step's event_types or keywords."""
        event_type = str(event.get("event_type") or "").lower()
        raw_log = str(event.get("raw_log") or "").lower()
        tags = [str(t).lower() for t in (event.get("tags") or [])]

        # Check event_type match
        for et in step.event_types:
            if et.lower() in event_type or event_type in et.lower():
                return True

        # Check keyword match in raw_log or tags
        for kw in step.keywords:
            kw_lower = kw.lower()
            if kw_lower in raw_log:
                return True
            if any(kw_lower in tag for tag in tags):
                return True

        return False

    def _chain_confidence(self, match_ratio: float, matched_events: int, total_events: int) -> float:
        """Confidence: higher when ratio is higher and supporting events are denser."""
        ratio_weight = match_ratio * 0.7
        density = min(0.3, (matched_events / max(total_events, 1)) * 0.3)
        return min(1.0, round(ratio_weight + density, 3))
