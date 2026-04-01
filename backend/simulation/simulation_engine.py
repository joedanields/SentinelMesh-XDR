"""Simulation orchestration engine."""
from __future__ import annotations
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List, Optional

from .brute_force_simulator import BruteForceSimulator
from .data_exfiltration_simulator import DataExfiltrationSimulator
from .lateral_movement_simulator import LateralMovementSimulator
from .port_scan_simulator import PortScanSimulator
from .sql_injection_simulator import SQLInjectionSimulator

logger = logging.getLogger(__name__)


@dataclass
class DetectionReport:
    scenario: str
    total_events: int
    detected_events: int
    missed_events: int
    false_positives: int
    precision: float
    recall: float
    f1_score: float
    detection_details: List[Dict[str, Any]] = field(default_factory=list)


class SimulationEngine:
    """Orchestrates all attack simulators and evaluates detection coverage."""

    def __init__(self, event_delay_ms: float = 0.0) -> None:
        self.event_delay_ms = event_delay_ms
        self._scenario_map = {
            "brute_force": BruteForceSimulator,
            "sql_injection": SQLInjectionSimulator,
            "port_scan": PortScanSimulator,
            "lateral_movement": LateralMovementSimulator,
            "data_exfiltration": DataExfiltrationSimulator,
        }

    def list_scenarios(self) -> List[str]:
        return list(self._scenario_map.keys()) + ["full_apt_chain"]

    def run_scenario(self, name: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        params = params or {}
        if name == "full_apt_chain":
            return self._run_full_apt_chain(params)
        cls = self._scenario_map.get(name)
        if cls is None:
            raise ValueError(f"Unknown scenario: {name}. Available: {self.list_scenarios()}")
        init_keys = {"target_host", "attacker_ip", "start_time", "seed"}
        init_params = {k: v for k, v in params.items() if k in init_keys}
        sim_params = {k: v for k, v in params.items() if k not in init_keys}
        simulator = cls(**init_params)
        logs = simulator.simulate(**sim_params)
        logger.info("Scenario '%s' generated %d events", name, len(logs))
        if self.event_delay_ms > 0:
            time.sleep(self.event_delay_ms / 1000.0 * len(logs))
        return logs

    def _run_full_apt_chain(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        from datetime import datetime, timezone
        base_time = params.get("start_time") or (datetime.now(timezone.utc) - timedelta(hours=6))
        attacker_ip = params.get("attacker_ip")
        all_logs: List[Dict[str, Any]] = []

        # Phase 1: Reconnaissance
        ps = PortScanSimulator(attacker_ip=attacker_ip, start_time=base_time, seed=params.get("seed"))
        all_logs.extend(ps.simulate(scan_type="version"))

        # Phase 2: Initial access via brute force
        bf_time = base_time + timedelta(minutes=30)
        bf = BruteForceSimulator(attacker_ip=attacker_ip, start_time=bf_time)
        all_logs.extend(bf.simulate(attack_type="ssh"))

        # Phase 3: Lateral movement
        lm_time = base_time + timedelta(hours=1, minutes=30)
        lm = LateralMovementSimulator(attacker_ip=attacker_ip, start_time=lm_time)
        all_logs.extend(lm.simulate())

        # Phase 4: Data exfiltration
        de_time = base_time + timedelta(hours=3)
        de = DataExfiltrationSimulator(attacker_ip=attacker_ip, start_time=de_time, data_volume_mb=100)
        all_logs.extend(de.simulate())

        all_logs.sort(key=lambda x: x["timestamp"])
        logger.info("Full APT chain generated %d events", len(all_logs))
        return all_logs

    def evaluate_detection(
        self,
        generated_logs: List[Dict[str, Any]],
        detected_log_ids: List[str],
    ) -> DetectionReport:
        total = len(generated_logs)
        detected_set = set(detected_log_ids)
        gen_ids = {l["id"] for l in generated_logs}
        true_positives = len(gen_ids & detected_set)
        false_negatives = len(gen_ids - detected_set)
        false_positives = len(detected_set - gen_ids)
        precision = true_positives / max(1, true_positives + false_positives)
        recall = true_positives / max(1, total)
        f1 = 2 * precision * recall / max(1e-9, precision + recall)
        scenario = generated_logs[0].get("attack_vector", "unknown") if generated_logs else "unknown"
        return DetectionReport(
            scenario=scenario,
            total_events=total,
            detected_events=true_positives,
            missed_events=false_negatives,
            false_positives=false_positives,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
        )
