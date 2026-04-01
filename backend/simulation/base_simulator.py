"""Abstract base class for all attack simulators."""

from __future__ import annotations

import random
import string
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Common data pools used across simulators
# ---------------------------------------------------------------------------

_USERNAMES = [
    "admin", "root", "administrator", "user", "guest", "test", "oracle",
    "postgres", "mysql", "service", "backup", "deploy", "devops", "jenkins",
    "ansible", "ubuntu", "centos", "ec2-user", "pi", "nagios", "zabbix",
]

_HOSTNAMES = [
    "web-prod-01", "web-prod-02", "db-primary", "db-replica", "auth-server",
    "api-gateway", "mail-server", "vpn-gateway", "fileserver-01", "dc-01",
    "monitoring", "backup-server", "jenkins-ci", "k8s-master", "k8s-node-01",
    "k8s-node-02", "app-server-01", "app-server-02", "loadbalancer", "proxy",
]

_INTERNAL_SUBNETS = ["10.0.1", "10.0.2", "10.0.3", "192.168.1", "172.16.0"]
_EXTERNAL_IPS = [
    "185.220.101.34", "45.33.32.156", "198.51.100.42", "203.0.113.77",
    "91.108.4.200", "185.130.44.108", "194.165.16.79", "77.247.181.162",
    "162.247.74.200", "176.10.104.240", "107.189.10.143", "51.75.144.43",
]


def _rand_internal_ip(subnet: Optional[str] = None) -> str:
    subnet = subnet or random.choice(_INTERNAL_SUBNETS)
    return f"{subnet}.{random.randint(2, 254)}"


def _rand_external_ip() -> str:
    return random.choice(_EXTERNAL_IPS)


def _rand_hostname() -> str:
    return random.choice(_HOSTNAMES)


def _rand_username() -> str:
    return random.choice(_USERNAMES)


def _rand_id() -> str:
    return str(uuid.uuid4())


class BaseSimulator(ABC):
    """
    Abstract base for all attack scenario simulators.

    Subclasses implement :meth:`simulate` which returns a list of normalised
    log dicts that can be fed directly into the ingestion pipeline.
    """

    #: Human-readable name used by SimulationEngine
    scenario_name: str = "base"

    def __init__(
        self,
        *,
        target_host: Optional[str] = None,
        attacker_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        seed: Optional[int] = None,
    ) -> None:
        if seed is not None:
            random.seed(seed)
        self.target_host = target_host or _rand_hostname()
        self.attacker_ip = attacker_ip or _rand_external_ip()
        self.start_time = start_time or datetime.now(timezone.utc) - timedelta(hours=1)

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def simulate(self, **params: Any) -> List[Dict[str, Any]]:
        """Run the simulation and return a list of log event dicts."""

    # ------------------------------------------------------------------
    # Helpers available to all subclasses
    # ------------------------------------------------------------------

    def generate_logs(self, count: int, **overrides: Any) -> List[Dict[str, Any]]:
        """Generate *count* generic log entries using the common template."""
        logs: List[Dict[str, Any]] = []
        for i in range(count):
            logs.append(self._log_template(offset_seconds=i * random.uniform(0.5, 5), **overrides))
        return logs

    def _log_template(
        self,
        *,
        offset_seconds: float = 0.0,
        event_type: str = "generic",
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        username: Optional[str] = None,
        hostname: Optional[str] = None,
        message: str = "",
        severity: str = "info",
        **extra: Any,
    ) -> Dict[str, Any]:
        ts = self.start_time + timedelta(seconds=offset_seconds)
        return {
            "id": _rand_id(),
            "timestamp": ts.isoformat(),
            "event_type": event_type,
            "source_ip": source_ip or self.attacker_ip,
            "dest_ip": dest_ip or _rand_internal_ip(),
            "username": username or _rand_username(),
            "hostname": hostname or self.target_host,
            "message": message,
            "severity": severity,
            "simulated": True,
            **extra,
        }

    # ------------------------------------------------------------------
    # Timestamp helpers
    # ------------------------------------------------------------------

    def _jittered_timestamps(
        self, count: int, base: Optional[datetime] = None, max_interval: float = 10.0
    ) -> List[datetime]:
        """Return *count* monotonically increasing timestamps with random jitter."""
        ts = base or self.start_time
        result: List[datetime] = []
        for _ in range(count):
            ts = ts + timedelta(seconds=random.uniform(0.1, max_interval))
            result.append(ts)
        return result

    def _syslog_line(self, ts: datetime, hostname: str, process: str, message: str) -> str:
        month_abbr = ts.strftime("%b")
        day = ts.strftime("%d").lstrip("0").rjust(2)
        time_part = ts.strftime("%H:%M:%S")
        return f"{month_abbr} {day} {time_part} {hostname} {process}: {message}"

    def _random_port(self, *, privileged: bool = False) -> int:
        if privileged:
            return random.choice([21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 3306, 5432, 6379, 8080])
        return random.randint(1024, 65535)

    @staticmethod
    def _random_string(length: int = 8) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
