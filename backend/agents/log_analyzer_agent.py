"""Log Analyzer Agent – extracts patterns, entities and anomalies from log data."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

import structlog

from .base_agent import AgentResult, BaseAgent

logger = structlog.get_logger(__name__)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_RE = re.compile(r"(?:user|username|account)[=:\s]+([A-Za-z0-9_@.\-]+)", re.I)
PROC_RE = re.compile(r"(?:process|cmd|command|exec)[=:\s]+([A-Za-z0-9_.\-\/\\]+)", re.I)
FAIL_RE = re.compile(r"\b(fail(?:ed|ure)?|denied|invalid|unauthorized|error|exception)\b", re.I)
PRIV_RE = re.compile(r"\b(root|admin(?:istrat(?:or|ive))?|sudo|su\b|privilege|elevated)\b", re.I)

SYSTEM_PROMPT = """You are an expert cybersecurity log analyst integrated into SentinelMesh XDR.

Your task is to analyse raw log entries and extract structured security intelligence.

For every analysis you MUST return a valid JSON object with these exact keys:
{
  "event_type": "<login|network|process|file|auth|dns|http|other>",
  "log_source": "<syslog|windows_event|firewall|web_server|edr|custom>",
  "entities": {
    "ips": ["<ip1>", ...],
    "users": ["<user1>", ...],
    "processes": ["<proc1>", ...],
    "hosts": ["<host1>", ...],
    "domains": ["<domain1>", ...]
  },
  "temporal_context": {
    "first_seen": "<ISO8601 or null>",
    "last_seen": "<ISO8601 or null>",
    "duration_seconds": <int or null>
  },
  "anomaly_indicators": ["<indicator1>", ...],
  "attack_pattern": "<pattern or null>",
  "multi_step_pattern": "<description or null>",
  "summary": "<1-2 sentence plain-English summary>",
  "severity": "<low|medium|high|critical>",
  "confidence": <float 0.0-1.0>
}

Rules:
- anomaly_indicators: list unusual characteristics (e.g. "failed_auth_burst", "off_hours_access")
- multi_step_pattern: if you detect a kill-chain sequence spanning these logs, describe it briefly
- Be concise. Output only the JSON, no prose.
"""


class LogAnalyzerAgent(BaseAgent):
    """Analyse log entries for security patterns, entities and anomalies."""

    REQUIRED_KEYS = [
        "event_type", "entities", "anomaly_indicators", "summary", "confidence"
    ]

    def __init__(self, model_name: str = "llama3") -> None:
        super().__init__(
            name="LogAnalyzerAgent",
            description="Analyses log entries for security patterns and insights.",
            model_name=model_name,
        )

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def build_prompt(self, input_data: Any) -> tuple[str, str]:
        if isinstance(input_data, list):
            log_text = "\n".join(
                str(entry) if not isinstance(entry, str) else entry
                for entry in input_data[:50]  # cap at 50 log lines
            )
            user_prompt = (
                f"Analyse the following {len(input_data)} log entries and return the JSON:\n\n"
                f"{log_text}"
            )
        else:
            user_prompt = f"Analyse this log entry and return the JSON:\n\n{input_data}"

        return SYSTEM_PROMPT, user_prompt

    def parse_response(self, raw_text: str) -> Dict[str, Any]:
        parsed = self._extract_json(raw_text)
        if not parsed:
            return {}
        # Normalise entities to lists
        entities = parsed.get("entities", {})
        for key in ("ips", "users", "processes", "hosts", "domains"):
            if key not in entities:
                entities[key] = []
        parsed["entities"] = entities
        return parsed

    async def analyze(self, input_data: Any) -> AgentResult:
        return await self._run_analysis(
            input_data,
            required_keys=self.REQUIRED_KEYS,
            fallback_fn=self._regex_fallback,
        )

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    async def summarize_batch(self, logs: List[str]) -> AgentResult:
        """Summarise a batch of logs focusing on bulk patterns."""
        summary_prompt_addon = (
            "\n\nFocus on bulk patterns: repeated failures, burst activity, multi-source attacks."
        )
        augmented = [f"[BATCH of {len(logs)} logs]\n" + "\n".join(logs[:100]) + summary_prompt_addon]
        return await self.analyze(augmented)

    async def detect_multistep_attack(self, logs: List[str]) -> AgentResult:
        """Detect multi-step attack sequences across a log batch."""
        header = "[MULTI-STEP ANALYSIS REQUEST] Look specifically for attack kill-chain sequences.\n"
        augmented = [header + "\n".join(logs[:200])]
        return await self.analyze(augmented)

    # ------------------------------------------------------------------
    # Regex-based fallback (AI unavailable)
    # ------------------------------------------------------------------

    def _regex_fallback(self, input_data: Any) -> Dict[str, Any]:
        log_text = (
            "\n".join(str(e) for e in input_data)
            if isinstance(input_data, list)
            else str(input_data)
        )

        ips = list(set(IP_RE.findall(log_text)))
        users = list(set(m.group(1) for m in USER_RE.finditer(log_text)))
        procs = list(set(m.group(1) for m in PROC_RE.finditer(log_text)))

        anomalies: List[str] = []
        if FAIL_RE.search(log_text):
            anomalies.append("auth_failure_detected")
        if PRIV_RE.search(log_text):
            anomalies.append("privileged_activity")
        if len(ips) > 5:
            anomalies.append("multi_source_activity")

        severity = "high" if anomalies else "low"

        return {
            "event_type": "other",
            "log_source": "custom",
            "entities": {"ips": ips, "users": users, "processes": procs, "hosts": [], "domains": []},
            "temporal_context": {"first_seen": None, "last_seen": None, "duration_seconds": None},
            "anomaly_indicators": anomalies,
            "attack_pattern": None,
            "multi_step_pattern": None,
            "summary": f"Regex-based analysis: {len(ips)} IPs, {len(users)} users, {len(anomalies)} anomalies.",
            "severity": severity,
            "confidence": 0.35,
        }
