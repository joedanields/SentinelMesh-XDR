"""Agent Orchestrator – coordinates all AI agents for comprehensive XDR analysis."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import OrderedDict
from typing import Any, Dict, List, Optional

import structlog

from .base_agent import AgentResult
from .correlation_agent import CorrelationAgent
from .forensics_agent import ForensicsAgent
from .incident_responder_agent import IncidentResponderAgent
from .log_analyzer_agent import LogAnalyzerAgent
from .threat_classifier_agent import ThreatClassifierAgent

logger = structlog.get_logger(__name__)

RESULT_CACHE_SIZE = 256


class AgentOrchestrator:
    """
    Manages all AI agents and orchestrates multi-agent analysis pipelines.

    Usage:
        orchestrator = AgentOrchestrator()
        report = await orchestrator.run_full_analysis(log_or_alert)
    """

    def __init__(self, model_name: str = "llama3") -> None:
        self.log_analyzer = LogAnalyzerAgent(model_name=model_name)
        self.threat_classifier = ThreatClassifierAgent(model_name=model_name)
        self.incident_responder = IncidentResponderAgent(model_name=model_name)
        self.forensics_agent = ForensicsAgent(model_name=model_name)
        self.correlation_agent = CorrelationAgent(model_name=model_name)

        # LRU-style cache keyed by hash of input repr
        self._cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()

        # Orchestrator-level metrics
        self._metrics: Dict[str, Any] = {
            "total_analyses": 0,
            "cache_hits": 0,
            "total_elapsed": 0.0,
            "agent_failures": 0,
        }

        self._log = logger.bind(component="AgentOrchestrator")

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run_full_analysis(self, input_data: Any) -> Dict[str, Any]:
        """
        Run all agents against the input in the optimal order and return a
        merged comprehensive report.

        Pipeline:
          Stage 1 (parallel): LogAnalyzer + Correlation
          Stage 2 (parallel, uses Stage-1 results): ThreatClassifier + Forensics
          Stage 3 (sequential): IncidentResponder (needs classifier output)
        """
        t0 = time.monotonic()
        analysis_id = str(uuid.uuid4())
        self._metrics["total_analyses"] += 1

        cache_key = self._cache_key(input_data)
        if cache_key in self._cache:
            self._metrics["cache_hits"] += 1
            self._log.info("cache_hit", analysis_id=analysis_id)
            return self._cache[cache_key]

        self._log.info("full_analysis_start", analysis_id=analysis_id)

        # ---- Stage 1: parallel log analysis + correlation ----
        log_result, correlation_result = await asyncio.gather(
            self._safe_analyze(self.log_analyzer, input_data),
            self._safe_analyze(self.correlation_agent, input_data if isinstance(input_data, list) else [input_data]),
            return_exceptions=False,
        )

        # Build enriched input for downstream agents
        classifier_input = self._build_classifier_input(input_data, log_result)

        # ---- Stage 2: parallel threat classification + forensics ----
        classifier_result, forensics_result = await asyncio.gather(
            self._safe_analyze(self.threat_classifier, classifier_input),
            self._safe_analyze(self.forensics_agent, {
                "logs": input_data if isinstance(input_data, list) else [input_data],
                "alerts": [],
                "incident_id": analysis_id,
            }),
            return_exceptions=False,
        )

        # ---- Stage 3: incident response (needs classifier output) ----
        responder_input = self._build_responder_input(classifier_result, log_result)
        responder_result = await self._safe_analyze(self.incident_responder, responder_input)

        elapsed = time.monotonic() - t0
        self._metrics["total_elapsed"] += elapsed

        report = self._merge_results(
            analysis_id=analysis_id,
            elapsed=elapsed,
            log_result=log_result,
            correlation_result=correlation_result,
            classifier_result=classifier_result,
            forensics_result=forensics_result,
            responder_result=responder_result,
        )

        self._store_cache(cache_key, report)
        self._log.info(
            "full_analysis_complete",
            analysis_id=analysis_id,
            elapsed=round(elapsed, 3),
            overall_confidence=round(report.get("overall_confidence", 0), 3),
        )
        return report

    # ------------------------------------------------------------------
    # Convenience single-agent methods
    # ------------------------------------------------------------------

    async def analyze_logs(self, logs: List[Any]) -> AgentResult:
        return await self._safe_analyze(self.log_analyzer, logs)

    async def classify_threat(self, event: Any) -> AgentResult:
        return await self._safe_analyze(self.threat_classifier, event)

    async def generate_playbook(self, threat_data: Dict[str, Any]) -> AgentResult:
        return await self._safe_analyze(self.incident_responder, threat_data)

    async def reconstruct_timeline(self, incident_data: Dict[str, Any]) -> AgentResult:
        return await self._safe_analyze(self.forensics_agent, incident_data)

    async def correlate_events(self, events: List[Any]) -> AgentResult:
        return await self._safe_analyze(self.correlation_agent, events)

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def get_metrics(self) -> Dict[str, Any]:
        total = self._metrics["total_analyses"] or 1
        return {
            "orchestrator": {
                "total_analyses": self._metrics["total_analyses"],
                "cache_hits": self._metrics["cache_hits"],
                "cache_hit_rate": self._metrics["cache_hits"] / total,
                "avg_elapsed_seconds": self._metrics["total_elapsed"] / total,
                "agent_failures": self._metrics["agent_failures"],
            },
            "agents": {
                agent.name: agent.get_metrics()
                for agent in (
                    self.log_analyzer,
                    self.threat_classifier,
                    self.incident_responder,
                    self.forensics_agent,
                    self.correlation_agent,
                )
            },
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _safe_analyze(self, agent: Any, input_data: Any) -> AgentResult:
        """Wrap agent.analyze() and catch unexpected exceptions."""
        try:
            result = await agent.analyze(input_data)
            if not result.success:
                self._metrics["agent_failures"] += 1
            return result
        except Exception as exc:  # noqa: BLE001
            self._metrics["agent_failures"] += 1
            self._log.error("agent_exception", agent=agent.name, error=str(exc))
            from .base_agent import AgentResult  # avoid circular import at module level
            return AgentResult(
                agent_name=agent.name,
                success=False,
                data={},
                confidence=0.0,
                elapsed_seconds=0.0,
                model_used="none",
                error=str(exc),
            )

    def _build_classifier_input(self, original: Any, log_result: AgentResult) -> Dict[str, Any]:
        """Merge original input with log analysis for threat classification."""
        base: Dict[str, Any] = {}
        if isinstance(original, dict):
            base = dict(original)
        elif isinstance(original, list) and original:
            first = original[0]
            base = dict(first) if isinstance(first, dict) else {"raw_log": str(first)}
        else:
            base = {"raw_log": str(original)}

        if log_result.success:
            log_data = log_result.data
            base.setdefault("entities", log_data.get("entities", {}))
            base.setdefault("description", log_data.get("summary", ""))
            base.setdefault("tags", log_data.get("anomaly_indicators", []))
            base["log_analysis"] = log_data

        return base

    def _build_responder_input(
        self, classifier_result: AgentResult, log_result: AgentResult
    ) -> Dict[str, Any]:
        """Build incident responder input from classifier + log outputs."""
        data: Dict[str, Any] = {}
        if classifier_result.success:
            data = dict(classifier_result.data)
        if log_result.success:
            entities = log_result.data.get("entities", {})
            data.setdefault("entities", entities)
        return data

    def _merge_results(
        self,
        analysis_id: str,
        elapsed: float,
        log_result: AgentResult,
        correlation_result: AgentResult,
        classifier_result: AgentResult,
        forensics_result: AgentResult,
        responder_result: AgentResult,
    ) -> Dict[str, Any]:
        """Merge all agent results into a unified report with confidence weighting."""
        results = [log_result, correlation_result, classifier_result, forensics_result, responder_result]
        successful = [r for r in results if r.success]

        # Confidence-weighted average
        overall_confidence = (
            sum(r.confidence for r in successful) / len(successful)
            if successful
            else 0.0
        )

        # Aggregate all IOCs
        all_iocs: List[str] = []
        if classifier_result.success:
            all_iocs.extend(classifier_result.data.get("indicators", []))

        # Aggregate MITRE mappings
        mitre_mappings: List[Dict[str, Any]] = []
        if classifier_result.success:
            mitre = classifier_result.data.get("mitre_mapping")
            if mitre:
                mitre_mappings.append(mitre)
        if forensics_result.success:
            for ttp in forensics_result.data.get("ttps", []):
                mitre_mappings.append({
                    "tactic": ttp.get("tactic"),
                    "technique_id": ttp.get("technique_id"),
                    "technique_name": ttp.get("technique_name"),
                })

        # Deduplicate MITRE by technique_id
        seen_techniques: set = set()
        deduped_mitre: List[Dict[str, Any]] = []
        for m in mitre_mappings:
            tid = m.get("technique_id", "")
            if tid and tid not in seen_techniques:
                seen_techniques.add(tid)
                deduped_mitre.append(m)

        return {
            "analysis_id": analysis_id,
            "overall_confidence": round(overall_confidence, 3),
            "elapsed_seconds": round(elapsed, 3),
            "successful_agents": len(successful),
            "total_agents": len(results),
            "log_analysis": log_result.to_dict(),
            "threat_classification": classifier_result.to_dict(),
            "incident_response": responder_result.to_dict(),
            "forensics": forensics_result.to_dict(),
            "correlation": correlation_result.to_dict(),
            "aggregated": {
                "all_iocs": list(set(all_iocs)),
                "mitre_techniques": deduped_mitre,
                "severity": classifier_result.data.get("severity") if classifier_result.success else None,
                "threat_category": classifier_result.data.get("category") if classifier_result.success else None,
                "blast_radius": (
                    responder_result.data.get("impact_assessment", {}).get("blast_radius")
                    if responder_result.success
                    else None
                ),
            },
        }

    def _cache_key(self, input_data: Any) -> str:
        raw = repr(input_data)[:4096]
        return uuid.uuid5(uuid.NAMESPACE_DNS, raw).hex

    def _store_cache(self, key: str, value: Dict[str, Any]) -> None:
        if key in self._cache:
            self._cache.move_to_end(key)
        else:
            if len(self._cache) >= RESULT_CACHE_SIZE:
                self._cache.popitem(last=False)
            self._cache[key] = value
