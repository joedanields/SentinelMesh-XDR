"""Threat intelligence module – IoCs, malicious IPs, ATT&CK mappings, enrichment."""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass
class ThreatInfo:
    indicator: str
    indicator_type: str          # "ip" | "domain" | "hash" | "url" | "keyword"
    is_malicious: bool
    category: str                # e.g. "c2", "scanner", "malware_dist"
    score: float                 # 0–100
    description: str = ""
    mitre_techniques: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "is_malicious": self.is_malicious,
            "category": self.category,
            "score": self.score,
            "description": self.description,
            "mitre_techniques": self.mitre_techniques,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": self.tags,
        }


@dataclass
class IoC:
    ioc_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    indicator: str = ""
    indicator_type: str = ""
    matched_field: str = ""
    matched_value: str = ""
    threat_info: ThreatInfo | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_id": self.ioc_id,
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "matched_field": self.matched_field,
            "matched_value": self.matched_value,
            "threat_info": self.threat_info.to_dict() if self.threat_info else None,
        }


# ---------------------------------------------------------------------------
# Sample threat intelligence data
# ---------------------------------------------------------------------------

_MALICIOUS_IPS: list[dict[str, Any]] = [
    {"ip": "185.220.101.1",  "category": "tor_exit",      "score": 75, "desc": "Known Tor exit node"},
    {"ip": "185.220.101.2",  "category": "tor_exit",      "score": 75, "desc": "Known Tor exit node"},
    {"ip": "194.165.16.10",  "category": "scanner",       "score": 80, "desc": "Mass internet scanner"},
    {"ip": "194.165.16.11",  "category": "scanner",       "score": 80, "desc": "Mass internet scanner"},
    {"ip": "45.153.160.2",   "category": "c2",            "score": 95, "desc": "Active C2 server",    "mitre": ["T1071", "T1090"]},
    {"ip": "45.153.160.3",   "category": "c2",            "score": 95, "desc": "Active C2 server",    "mitre": ["T1071", "T1090"]},
    {"ip": "198.54.117.200", "category": "spam",          "score": 60, "desc": "Spam source"},
    {"ip": "198.54.117.201", "category": "spam",          "score": 60, "desc": "Spam source"},
    {"ip": "91.108.4.1",     "category": "malware_dist",  "score": 90, "desc": "Malware distribution", "mitre": ["T1105"]},
    {"ip": "91.108.4.2",     "category": "malware_dist",  "score": 90, "desc": "Malware distribution", "mitre": ["T1105"]},
    {"ip": "5.188.206.100",  "category": "bruteforce",    "score": 85, "desc": "SSH/RDP brute force", "mitre": ["T1110"]},
    {"ip": "5.188.206.101",  "category": "bruteforce",    "score": 85, "desc": "SSH/RDP brute force", "mitre": ["T1110"]},
    {"ip": "103.21.244.1",   "category": "phishing",      "score": 88, "desc": "Phishing infrastructure", "mitre": ["T1566"]},
    {"ip": "103.21.244.2",   "category": "phishing",      "score": 88, "desc": "Phishing infrastructure", "mitre": ["T1566"]},
    {"ip": "162.55.35.30",   "category": "scanner",       "score": 70, "desc": "Vulnerability scanner"},
    {"ip": "162.55.35.31",   "category": "scanner",       "score": 70, "desc": "Vulnerability scanner"},
    {"ip": "193.32.127.50",  "category": "c2",            "score": 92, "desc": "Cobalt Strike C2",   "mitre": ["T1071", "T1219"]},
    {"ip": "193.32.127.51",  "category": "c2",            "score": 92, "desc": "Cobalt Strike C2",   "mitre": ["T1071", "T1219"]},
    {"ip": "209.141.42.100", "category": "anonymizer",    "score": 65, "desc": "VPN/proxy service"},
    {"ip": "209.141.42.101", "category": "anonymizer",    "score": 65, "desc": "VPN/proxy service"},
    # Additional entries for variety
    {"ip": "185.107.94.1",   "category": "ransomware",    "score": 98, "desc": "Ransomware C2",      "mitre": ["T1486", "T1071"]},
    {"ip": "185.107.94.2",   "category": "ransomware",    "score": 98, "desc": "Ransomware C2",      "mitre": ["T1486", "T1071"]},
    {"ip": "77.73.133.70",   "category": "botnet",        "score": 87, "desc": "Botnet C2",          "mitre": ["T1583", "T1090"]},
    {"ip": "77.73.133.71",   "category": "botnet",        "score": 87, "desc": "Botnet C2",          "mitre": ["T1583", "T1090"]},
    {"ip": "213.32.122.100", "category": "exploit_kit",   "score": 91, "desc": "Exploit kit host",   "mitre": ["T1190"]},
    {"ip": "5.34.179.60",    "category": "credential_theft", "score": 89, "desc": "Credential theft portal", "mitre": ["T1078"]},
    {"ip": "176.58.100.1",   "category": "cryptominer",   "score": 72, "desc": "Cryptomining pool",  "mitre": ["T1496"]},
    {"ip": "176.58.100.2",   "category": "cryptominer",   "score": 72, "desc": "Cryptomining pool",  "mitre": ["T1496"]},
    {"ip": "185.244.25.200", "category": "scanner",       "score": 68, "desc": "Port scanner"},
    {"ip": "185.244.25.201", "category": "scanner",       "score": 68, "desc": "Port scanner"},
    # 100+ entries via range expansion below
]

# Expand to 100+ entries
for _i in range(3, 80):
    _MALICIOUS_IPS.append({
        "ip": f"10.200.{_i}.1",
        "category": "internal_scanner" if _i % 2 == 0 else "suspicious",
        "score": 55 + (_i % 30),
        "desc": f"Suspicious internal host group {_i}",
    })

_MALICIOUS_DOMAINS: list[dict[str, Any]] = [
    {"domain": "evil-c2-server.xyz",        "category": "c2",           "score": 95, "mitre": ["T1071"]},
    {"domain": "malware-domain.ru",         "category": "malware_dist", "score": 90, "mitre": ["T1105"]},
    {"domain": "suspicious-exfil.net",      "category": "exfiltration", "score": 88, "mitre": ["T1048"]},
    {"domain": "phishing-login.com",        "category": "phishing",     "score": 85, "mitre": ["T1566"]},
    {"domain": "update-now-patch.org",      "category": "phishing",     "score": 82, "mitre": ["T1566"]},
    {"domain": "free-vpn-proxy.net",        "category": "anonymizer",   "score": 60},
    {"domain": "cdn-delivery-fast.xyz",     "category": "typosquatting","score": 78},
    {"domain": "windowsupdate-cdn.org",     "category": "typosquatting","score": 80},
    {"domain": "secure-paypal-login.com",   "category": "phishing",     "score": 90, "mitre": ["T1566"]},
    {"domain": "ransomware-payment.onion",  "category": "ransomware",   "score": 99, "mitre": ["T1486"]},
]

_ATTACK_SIGNATURES: dict[str, dict[str, Any]] = {
    "SIG_SQLI_UNION":    {"pattern": r"(?i)union.{0,20}select", "technique": "T1190", "severity": "high"},
    "SIG_SQLI_TAUTOL":   {"pattern": r"(?i)'\s*or\s*'1'\s*=\s*'1", "technique": "T1190", "severity": "high"},
    "SIG_XSS_SCRIPT":    {"pattern": r"(?i)<script[^>]*>", "technique": "T1059.007", "severity": "medium"},
    "SIG_CMD_INJECT":    {"pattern": r"(?i);\s*(ls|cat|id|whoami|uname)", "technique": "T1059", "severity": "high"},
    "SIG_PATH_TRAVERSAL":{"pattern": r"\.\./|%2e%2e%2f", "technique": "T1190", "severity": "high"},
    "SIG_LOG4SHELL":     {"pattern": r"\$\{jndi:", "technique": "T1190", "severity": "critical"},
    "SIG_SHELLSHOCK":    {"pattern": r"\(\s*\)\s*\{.*\}", "technique": "T1190", "severity": "critical"},
    "SIG_HEARTBLEED":    {"pattern": r"(?i)heartbeat.*overflow", "technique": "T1190", "severity": "critical"},
    "SIG_MIMIKATZ":      {"pattern": r"(?i)(sekurlsa|lsadump|kerberos::)", "technique": "T1003", "severity": "critical"},
    "SIG_COBALT_STRIKE": {"pattern": r"(?i)(beacon|cobaltstrike|cs\.exe)", "technique": "T1219", "severity": "critical"},
}

_MITRE_TECHNIQUES: dict[str, dict[str, Any]] = {
    "T1059":      {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.007":  {"name": "JavaScript", "tactic": "Execution"},
    "T1071":      {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.004":  {"name": "DNS", "tactic": "Command and Control"},
    "T1078":      {"name": "Valid Accounts", "tactic": "Privilege Escalation"},
    "T1083":      {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1090":      {"name": "Proxy", "tactic": "Command and Control"},
    "T1105":      {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1110":      {"name": "Brute Force", "tactic": "Credential Access"},
    "T1136":      {"name": "Create Account", "tactic": "Persistence"},
    "T1190":      {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1219":      {"name": "Remote Access Software", "tactic": "Command and Control"},
    "T1486":      {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1496":      {"name": "Resource Hijacking", "tactic": "Impact"},
    "T1048":      {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1003":      {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1562.004":  {"name": "Disable or Modify System Firewall", "tactic": "Defense Evasion"},
    "T1566":      {"name": "Phishing", "tactic": "Initial Access"},
    "T1583":      {"name": "Acquire Infrastructure", "tactic": "Resource Development"},
    "T1595":      {"name": "Active Scanning", "tactic": "Reconnaissance"},
}


# ---------------------------------------------------------------------------
# ThreatIntelligence
# ---------------------------------------------------------------------------


class ThreatIntelligence:
    """In-memory threat intelligence database with IoC matching and enrichment.

    Data is pre-loaded from the built-in lists above.  Additional entries can
    be added at runtime via :meth:`add_ip`, :meth:`add_domain`, and
    :meth:`add_ioc`.  The full database can be persisted and reloaded from a
    JSON file via :meth:`save` / :meth:`load`.
    """

    def __init__(self, persist_path: str = "data/threat_intel.json") -> None:
        self.persist_path = Path(persist_path)
        self._ip_db: dict[str, ThreatInfo] = {}
        self._domain_db: dict[str, ThreatInfo] = {}
        self._custom_iocs: list[dict[str, Any]] = []
        self._compiled_sigs: dict[str, tuple[re.Pattern, dict[str, Any]]] = {}
        self._log = logger.bind(component="ThreatIntelligence")
        self._load_builtin()
        self._compile_signatures()

    # ------------------------------------------------------------------
    # Bootstrap
    # ------------------------------------------------------------------

    def _load_builtin(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        for entry in _MALICIOUS_IPS:
            ti = ThreatInfo(
                indicator=entry["ip"],
                indicator_type="ip",
                is_malicious=True,
                category=entry.get("category", "unknown"),
                score=float(entry.get("score", 50)),
                description=entry.get("desc", ""),
                mitre_techniques=entry.get("mitre", []),
                first_seen=now,
                last_seen=now,
                tags=["builtin"],
            )
            self._ip_db[entry["ip"]] = ti

        for entry in _MALICIOUS_DOMAINS:
            ti = ThreatInfo(
                indicator=entry["domain"],
                indicator_type="domain",
                is_malicious=True,
                category=entry.get("category", "unknown"),
                score=float(entry.get("score", 50)),
                description=entry.get("desc", ""),
                mitre_techniques=entry.get("mitre", []),
                first_seen=now,
                last_seen=now,
                tags=["builtin"],
            )
            self._domain_db[entry["domain"]] = ti

        self._log.info(
            "built-in TI loaded",
            ips=len(self._ip_db),
            domains=len(self._domain_db),
        )

    def _compile_signatures(self) -> None:
        for sig_id, info in _ATTACK_SIGNATURES.items():
            try:
                compiled = re.compile(info["pattern"], re.IGNORECASE | re.DOTALL)
                self._compiled_sigs[sig_id] = (compiled, info)
            except re.error as exc:
                self._log.warning("invalid signature pattern", sig_id=sig_id, error=str(exc))

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def check_ip(self, ip: str) -> ThreatInfo | None:
        """Return :class:`ThreatInfo` for *ip* or ``None`` if not found."""
        return self._ip_db.get(ip.strip())

    def check_domain(self, domain: str) -> ThreatInfo | None:
        """Return :class:`ThreatInfo` for *domain* or ``None`` if not found."""
        domain = domain.strip().lower()
        # Exact match
        if domain in self._domain_db:
            return self._domain_db[domain]
        # Subdomain match: check if any known malicious domain is a suffix
        for known in self._domain_db:
            if domain.endswith(f".{known}") or domain == known:
                return self._domain_db[known]
        return None

    def match_ioc(self, log: dict[str, Any]) -> list[IoC]:
        """Scan all log fields for known IoCs and attack signatures.

        Returns a list of :class:`IoC` objects for each match found.
        """
        matches: list[IoC] = []
        log_text = " ".join(str(v) for v in log.values() if isinstance(v, (str, int, float)))

        # IP lookups
        ip_candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_text)
        for ip in set(ip_candidates):
            ti = self.check_ip(ip)
            if ti:
                matches.append(IoC(
                    indicator=ip,
                    indicator_type="ip",
                    matched_field="auto_extracted",
                    matched_value=ip,
                    threat_info=ti,
                ))

        # Domain lookups
        domain_candidates = re.findall(
            r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|xyz|ru|onion|io|co)\b",
            log_text, re.IGNORECASE,
        )
        for domain in set(domain_candidates):
            ti = self.check_domain(domain)
            if ti:
                matches.append(IoC(
                    indicator=domain,
                    indicator_type="domain",
                    matched_field="auto_extracted",
                    matched_value=domain,
                    threat_info=ti,
                ))

        # Attack signature matching
        for sig_id, (pattern, info) in self._compiled_sigs.items():
            if pattern.search(log_text):
                sev = info.get("severity", "medium")
                technique = info.get("technique", "")
                fake_ti = ThreatInfo(
                    indicator=sig_id,
                    indicator_type="signature",
                    is_malicious=True,
                    category="attack_signature",
                    score={"critical": 95, "high": 80, "medium": 60, "low": 40}.get(sev, 60),
                    description=f"Attack signature {sig_id} matched",
                    mitre_techniques=[technique] if technique else [],
                )
                matches.append(IoC(
                    indicator=sig_id,
                    indicator_type="signature",
                    matched_field="message",
                    matched_value=log_text[:100],
                    threat_info=fake_ti,
                ))

        # Custom IoC matching
        for custom in self._custom_iocs:
            value = custom.get("value", "")
            if value and value in log_text:
                fake_ti = ThreatInfo(
                    indicator=value,
                    indicator_type=custom.get("type", "keyword"),
                    is_malicious=True,
                    category=custom.get("category", "custom"),
                    score=float(custom.get("score", 70)),
                    description=custom.get("description", ""),
                )
                matches.append(IoC(
                    indicator=value,
                    indicator_type=custom.get("type", "keyword"),
                    matched_field="message",
                    matched_value=value,
                    threat_info=fake_ti,
                ))

        return matches

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    def add_context_to_log(self, log: dict[str, Any]) -> dict[str, Any]:
        """Enrich *log* in-place with threat intelligence context.

        Adds ``threat_intel`` key to ``parsed_fields`` if any matches found.
        """
        iocs = self.match_ioc(log)
        if not iocs:
            return log

        ti_context: dict[str, Any] = {
            "iocs": [ioc.to_dict() for ioc in iocs],
            "highest_score": max(ioc.threat_info.score for ioc in iocs if ioc.threat_info),
            "categories": list({ioc.threat_info.category for ioc in iocs if ioc.threat_info}),
            "mitre_techniques": list({
                t
                for ioc in iocs
                if ioc.threat_info
                for t in ioc.threat_info.mitre_techniques
            }),
        }

        if "parsed_fields" not in log or not isinstance(log["parsed_fields"], dict):
            log["parsed_fields"] = {}
        log["parsed_fields"]["threat_intel"] = ti_context

        # Bump severity if TI hit is high-confidence
        max_score = ti_context["highest_score"]
        if max_score >= 90 and log.get("severity") not in ("critical", "error"):
            log["severity"] = "critical"
        elif max_score >= 70 and log.get("severity") == "info":
            log["severity"] = "warning"

        return log

    def get_mitre_info(self, technique_id: str) -> dict[str, Any]:
        """Return ATT&CK technique metadata for *technique_id*."""
        return _MITRE_TECHNIQUES.get(technique_id, {})

    # ------------------------------------------------------------------
    # Runtime additions
    # ------------------------------------------------------------------

    def add_ip(self, ip: str, category: str, score: float, description: str = "") -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._ip_db[ip] = ThreatInfo(
            indicator=ip, indicator_type="ip", is_malicious=True,
            category=category, score=score, description=description,
            first_seen=now, last_seen=now, tags=["custom"],
        )

    def add_domain(self, domain: str, category: str, score: float, description: str = "") -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._domain_db[domain.lower()] = ThreatInfo(
            indicator=domain, indicator_type="domain", is_malicious=True,
            category=category, score=score, description=description,
            first_seen=now, last_seen=now, tags=["custom"],
        )

    def add_ioc(self, value: str, ioc_type: str, category: str, score: float, description: str = "") -> None:
        self._custom_iocs.append({
            "value": value, "type": ioc_type, "category": category,
            "score": score, "description": description,
        })

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | None = None) -> None:
        target = Path(path or self.persist_path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "ips": {k: v.to_dict() for k, v in self._ip_db.items()
                        if "builtin" not in v.tags},          # skip built-ins
                "domains": {k: v.to_dict() for k, v in self._domain_db.items()
                            if "builtin" not in v.tags},
                "custom_iocs": self._custom_iocs,
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }
            with open(target, "w") as fh:
                json.dump(data, fh, indent=2)
            self._log.info("TI database saved", path=str(target))
        except Exception as exc:
            self._log.error("TI save failed", error=str(exc))

    def load(self, path: str | None = None) -> None:
        target = Path(path or self.persist_path)
        if not target.exists():
            return
        try:
            with open(target) as fh:
                data = json.load(fh)
            now = datetime.now(timezone.utc).isoformat()
            for k, v in data.get("ips", {}).items():
                self._ip_db[k] = ThreatInfo(**{**v, "tags": v.get("tags", []) + ["persisted"]})
            for k, v in data.get("domains", {}).items():
                self._domain_db[k] = ThreatInfo(**{**v, "tags": v.get("tags", []) + ["persisted"]})
            self._custom_iocs.extend(data.get("custom_iocs", []))
            self._log.info("TI database loaded", path=str(target))
        except Exception as exc:
            self._log.error("TI load failed", error=str(exc))

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        return {
            "malicious_ips": len(self._ip_db),
            "malicious_domains": len(self._domain_db),
            "custom_iocs": len(self._custom_iocs),
            "attack_signatures": len(self._compiled_sigs),
            "mitre_techniques": len(_MITRE_TECHNIQUES),
        }
