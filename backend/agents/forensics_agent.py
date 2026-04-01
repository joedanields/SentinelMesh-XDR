"""Forensics Agent – reconstructs attack timelines and generates forensic reports."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

from .base_agent import AgentResult, BaseAgent

logger = structlog.get_logger(__name__)

SYSTEM_PROMPT = """You are a digital forensics analyst for SentinelMesh XDR.

Your task is to reconstruct a complete attack timeline from the provided log/alert data.

Return ONLY this JSON structure (no prose):
{
  "timeline": [
    {
      "sequence": <int starting at 1>,
      "timestamp": "<ISO8601 or estimated>",
      "event": "<what happened>",
      "source_log": "<which log/alert this came from>",
      "significance": "<why this event matters forensically>"
    }
  ],
  "attack_chain": {
    "initial_compromise": {"timestamp": "<ISO8601 or null>", "method": "<description>"},
    "reconnaissance": {"timestamp": "<ISO8601 or null>", "method": "<description>"},
    "lateral_movement": [{"timestamp": "<ISO8601 or null>", "from_host": "<host>", "to_host": "<host>", "method": "<description>"}],
    "persistence": {"timestamp": "<ISO8601 or null>", "mechanism": "<description>"},
    "exfiltration": {"timestamp": "<ISO8601 or null>", "data": "<description>", "destination": "<destination>"}
  },
  "ttps": [
    {"tactic": "<name>", "technique_id": "<T####>", "technique_name": "<name>", "evidence": "<which log proves this>"}
  ],
  "evidence_sources": [
    {"source_type": "<log_type>", "source_id": "<id or path>", "relevance": "<high|medium|low>", "description": "<what it shows>"}
  ],
  "forensic_report": {
    "executive_summary": "<2-3 sentence summary for executives>",
    "technical_summary": "<detailed technical narrative>",
    "key_findings": ["<finding1>", ...],
    "gaps_in_evidence": ["<gap1>", ...],
    "recommendations": ["<rec1>", ...]
  },
  "attacker_objectives": ["<obj1>", ...],
  "dwell_time_hours": <float or null>,
  "confidence": <float 0.0-1.0>
}

Guidelines:
- Order timeline strictly chronologically
- dwell_time_hours: time from initial compromise to detection
- Identify gaps where logs are missing
- Be precise about evidence vs inference
"""

TS_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"
)


class ForensicsAgent(BaseAgent):
    """Reconstruct attack timelines and generate forensic investigation reports."""

    REQUIRED_KEYS = [
        "timeline", "attack_chain", "ttps", "evidence_sources", "forensic_report", "confidence"
    ]

    def __init__(self, model_name: str = "llama3") -> None:
        super().__init__(
            name="ForensicsAgent",
            description="Reconstructs attack timelines and produces forensic reports.",
            model_name=model_name,
        )

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def build_prompt(self, input_data: Any) -> tuple[str, str]:
        if isinstance(input_data, dict):
            logs = input_data.get("logs", [])
            alerts = input_data.get("alerts", [])
            incident_id = input_data.get("incident_id", "unknown")

            logs_text = "\n".join(str(l) for l in logs[:100])
            alerts_text = "\n".join(str(a) for a in alerts[:20])

            user_prompt = (
                f"Reconstruct the attack timeline for incident {incident_id}.\n\n"
                f"=== ALERTS ({len(alerts)}) ===\n{alerts_text}\n\n"
                f"=== LOGS ({len(logs)}) ===\n{logs_text}"
            )
        elif isinstance(input_data, list):
            events_text = "\n".join(str(e) for e in input_data[:150])
            user_prompt = f"Reconstruct the attack timeline from these events:\n\n{events_text}"
        else:
            user_prompt = f"Reconstruct the attack timeline:\n\n{input_data}"

        return SYSTEM_PROMPT, user_prompt

    def parse_response(self, raw_text: str) -> Dict[str, Any]:
        parsed = self._extract_json(raw_text)
        if not parsed:
            return {}

        # Normalise structure
        parsed.setdefault("timeline", [])
        parsed.setdefault("ttps", [])
        parsed.setdefault("evidence_sources", [])
        parsed.setdefault("attacker_objectives", [])

        attack_chain = parsed.setdefault("attack_chain", {})
        for key in ("initial_compromise", "reconnaissance", "persistence", "exfiltration"):
            attack_chain.setdefault(key, {"timestamp": None, "method": None})
        attack_chain.setdefault("lateral_movement", [])

        forensic_report = parsed.setdefault("forensic_report", {})
        forensic_report.setdefault("executive_summary", "")
        forensic_report.setdefault("technical_summary", "")
        forensic_report.setdefault("key_findings", [])
        forensic_report.setdefault("gaps_in_evidence", [])
        forensic_report.setdefault("recommendations", [])

        return parsed

    async def analyze(self, input_data: Any) -> AgentResult:
        return await self._run_analysis(
            input_data,
            required_keys=self.REQUIRED_KEYS,
            fallback_fn=self._heuristic_fallback,
        )

    # ------------------------------------------------------------------
    # Heuristic fallback
    # ------------------------------------------------------------------

    def _heuristic_fallback(self, input_data: Any) -> Dict[str, Any]:
        """Build a minimal timeline by extracting timestamps from raw text."""
        if isinstance(input_data, dict):
            raw_sources = input_data.get("logs", []) + input_data.get("alerts", [])
        elif isinstance(input_data, list):
            raw_sources = input_data
        else:
            raw_sources = [str(input_data)]

        timeline_entries: List[Dict[str, Any]] = []
        seen_ts: List[datetime] = []

        for idx, entry in enumerate(raw_sources[:50]):
            text = str(entry)
            matches = TS_RE.findall(text)
            ts_str = matches[0] if matches else f"event-{idx + 1}"
            if matches:
                try:
                    ts_dt = datetime.fromisoformat(matches[0].replace("Z", "+00:00"))
                    seen_ts.append(ts_dt)
                except ValueError:
                    pass

            timeline_entries.append({
                "sequence": idx + 1,
                "timestamp": ts_str,
                "event": text[:120],
                "source_log": f"event_{idx}",
                "significance": "Extracted by heuristic fallback",
            })

        # Sort by timestamp if parseable
        timeline_entries.sort(key=lambda e: e["sequence"])

        dwell = None
        if len(seen_ts) >= 2:
            dwell = (max(seen_ts) - min(seen_ts)).total_seconds() / 3600.0

        return {
            "timeline": timeline_entries,
            "attack_chain": {
                "initial_compromise": {"timestamp": None, "method": "Unknown (AI unavailable)"},
                "reconnaissance": {"timestamp": None, "method": None},
                "lateral_movement": [],
                "persistence": {"timestamp": None, "mechanism": None},
                "exfiltration": {"timestamp": None, "data": None, "destination": None},
            },
            "ttps": [],
            "evidence_sources": [
                {"source_type": "raw_log", "source_id": "batch", "relevance": "high", "description": "Heuristic extraction"}
            ],
            "forensic_report": {
                "executive_summary": f"Heuristic timeline extracted from {len(raw_sources)} events.",
                "technical_summary": "AI-based analysis unavailable; timestamps extracted by regex.",
                "key_findings": [f"{len(timeline_entries)} events processed"],
                "gaps_in_evidence": ["Full AI forensics unavailable"],
                "recommendations": ["Run full AI analysis when Ollama is available"],
            },
            "attacker_objectives": [],
            "dwell_time_hours": dwell,
            "confidence": 0.25,
        }
