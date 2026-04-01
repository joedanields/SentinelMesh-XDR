"""Correlation Agent – links related security events across time and systems."""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

from .base_agent import AgentResult, BaseAgent

logger = structlog.get_logger(__name__)

SYSTEM_PROMPT = """You are an expert security event correlation analyst for SentinelMesh XDR.

Your job is to identify relationships between security events and group them into:
- Attack campaigns (multiple events belonging to the same intrusion)
- Lateral movement paths (attacker moving between hosts)
- Data flow anomalies (unusual data transfers)
- Event sessions (logically connected bursts of activity)

Return ONLY this JSON (no prose):
{
  "correlations": [
    {
      "correlation_id": "<uuid>",
      "type": "<campaign|lateral_movement|data_flow|session|pattern>",
      "related_event_ids": ["<id1>", ...],
      "description": "<what links these events>",
      "confidence": <float 0.0-1.0>
    }
  ],
  "campaigns": [
    {
      "campaign_id": "<uuid>",
      "name": "<descriptive name>",
      "event_ids": ["<id1>", ...],
      "start_time": "<ISO8601>",
      "end_time": "<ISO8601>",
      "attacker_ip": "<ip or null>",
      "targeted_assets": ["<asset1>", ...],
      "attack_objective": "<description>"
    }
  ],
  "sessions": [
    {
      "session_id": "<uuid>",
      "source_ip": "<ip>",
      "user": "<user or null>",
      "start_time": "<ISO8601>",
      "end_time": "<ISO8601>",
      "event_count": <int>,
      "risk_score": <float 0-10>,
      "anomalies": ["<anomaly1>", ...]
    }
  ],
  "graph_edges": [
    {"from_node": "<id>", "to_node": "<id>", "relationship": "<type>", "weight": <float>}
  ],
  "summary": "<overall narrative of what these correlated events represent>",
  "confidence": <float 0.0-1.0>
}
"""

SESSION_TIMEOUT_SECONDS = 1800  # 30 minutes


class CorrelationAgent(BaseAgent):
    """Link related security events across time and systems."""

    REQUIRED_KEYS = [
        "correlations", "campaigns", "sessions", "graph_edges", "confidence"
    ]

    def __init__(self, model_name: str = "llama3") -> None:
        super().__init__(
            name="CorrelationAgent",
            description="Correlates security events into campaigns and sessions.",
            model_name=model_name,
        )

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def build_prompt(self, input_data: Any) -> tuple[str, str]:
        if isinstance(input_data, list):
            events_text = "\n".join(
                (f"[{e.get('id', idx)}] {e.get('timestamp', '')} | {e.get('source', '')} | "
                 f"ip={e.get('ip_address', 'N/A')} user={e.get('user_id', 'N/A')} "
                 f"type={e.get('event_type', 'N/A')} | {str(e.get('raw_log', ''))[:100]}")
                if isinstance(e, dict)
                else f"[{idx}] {str(e)[:150]}"
                for idx, e in enumerate(input_data[:200])
            )
            user_prompt = (
                f"Correlate these {len(input_data)} security events into campaigns, "
                f"sessions and relationships:\n\n{events_text}"
            )
        else:
            user_prompt = f"Correlate these security events:\n\n{input_data}"

        return SYSTEM_PROMPT, user_prompt

    def parse_response(self, raw_text: str) -> Dict[str, Any]:
        parsed = self._extract_json(raw_text)
        if not parsed:
            return {}

        for key in ("correlations", "campaigns", "sessions", "graph_edges"):
            if key not in parsed:
                parsed[key] = []

        return parsed

    async def analyze(self, input_data: Any) -> AgentResult:
        return await self._run_analysis(
            input_data,
            required_keys=self.REQUIRED_KEYS,
            fallback_fn=self._heuristic_correlate,
        )

    # ------------------------------------------------------------------
    # Heuristic fallback correlation
    # ------------------------------------------------------------------

    def _heuristic_correlate(self, input_data: Any) -> Dict[str, Any]:
        """Group events by IP/user using simple heuristics."""
        events: List[Dict[str, Any]] = []
        if isinstance(input_data, list):
            for e in input_data:
                if isinstance(e, dict):
                    events.append(e)
                else:
                    events.append({"raw_log": str(e), "id": str(uuid.uuid4())})
        else:
            events = [{"raw_log": str(input_data), "id": str(uuid.uuid4())}]

        # Group by source_ip
        ip_groups: Dict[str, List[str]] = defaultdict(list)
        user_groups: Dict[str, List[str]] = defaultdict(list)

        for e in events:
            eid = e.get("id", str(uuid.uuid4()))
            ip = e.get("ip_address", "")
            user = e.get("user_id", "")
            if ip:
                ip_groups[ip].append(eid)
            if user:
                user_groups[user].append(eid)

        correlations: List[Dict[str, Any]] = []
        for ip, eids in ip_groups.items():
            if len(eids) > 1:
                correlations.append({
                    "correlation_id": str(uuid.uuid4()),
                    "type": "session",
                    "related_event_ids": eids,
                    "description": f"Multiple events from IP {ip}",
                    "confidence": 0.6,
                })

        for user, eids in user_groups.items():
            if len(eids) > 1:
                correlations.append({
                    "correlation_id": str(uuid.uuid4()),
                    "type": "session",
                    "related_event_ids": eids,
                    "description": f"Multiple events by user {user}",
                    "confidence": 0.55,
                })

        # Build sessions per source IP
        sessions: List[Dict[str, Any]] = []
        for ip, eids in ip_groups.items():
            ip_events = [e for e in events if e.get("ip_address") == ip]
            sessions.append({
                "session_id": str(uuid.uuid4()),
                "source_ip": ip,
                "user": ip_events[0].get("user_id") if ip_events else None,
                "start_time": None,
                "end_time": None,
                "event_count": len(eids),
                "risk_score": min(10.0, len(eids) * 0.5),
                "anomalies": [],
            })

        # Build simple graph edges
        graph_edges: List[Dict[str, Any]] = []
        for corr in correlations:
            eids = corr["related_event_ids"]
            for i in range(len(eids) - 1):
                graph_edges.append({
                    "from_node": eids[i],
                    "to_node": eids[i + 1],
                    "relationship": "followed_by",
                    "weight": 1.0,
                })

        return {
            "correlations": correlations,
            "campaigns": [],
            "sessions": sessions,
            "graph_edges": graph_edges,
            "summary": f"Heuristic correlation: {len(correlations)} groups across {len(events)} events.",
            "confidence": 0.35,
        }
