"""Port scan attack simulator (TCP SYN, UDP, version scans)."""

from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

from .base_simulator import BaseSimulator, _rand_internal_ip


# ---------------------------------------------------------------------------
# Well-known ports commonly probed during reconnaissance
# ---------------------------------------------------------------------------

_COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443,
    445, 465, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 8888, 9200, 27017,
]

_ALL_PORTS = list(range(1, 1025)) + _COMMON_PORTS

_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 88: "kerberos", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}

_CONNECTION_STATES = ["SYN_SENT", "RST_RECEIVED", "TIMEOUT", "OPEN", "FILTERED"]


class PortScanSimulator(BaseSimulator):
    """
    Simulates network port scanning.

    Scan types
    ----------
    * ``syn``      — TCP SYN (half-open) scan, fastest, stealthy
    * ``udp``      — UDP scan, slower, detects UDP services
    * ``version``  — Service/version detection scan (slower, more data)
    * ``full``     — Full TCP connect scan
    """

    scenario_name = "port_scan"

    def __init__(
        self,
        *,
        attacker_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
        scan_type: str = "syn",
        port_range: str = "common",
        start_time=None,
        seed: Optional[int] = None,
    ) -> None:
        super().__init__(
            attacker_ip=attacker_ip,
            start_time=start_time,
            seed=seed,
        )
        self.target_ip = target_ip or _rand_internal_ip()
        self.scan_type = scan_type.lower()
        self.port_range = port_range  # "common" | "all" | "custom:<ports>"

    # ------------------------------------------------------------------

    def simulate(self, **params: Any) -> List[Dict[str, Any]]:
        scan_type = params.get("scan_type", self.scan_type)
        dispatch = {
            "syn": self._syn_scan,
            "udp": self._udp_scan,
            "version": self._version_scan,
            "full": self._full_connect_scan,
        }
        fn = dispatch.get(scan_type, self._syn_scan)
        return fn()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_ports(self) -> List[int]:
        if self.port_range == "all":
            ports = _ALL_PORTS[:]
        elif self.port_range.startswith("custom:"):
            raw = self.port_range.split(":", 1)[1]
            ports = [int(p.strip()) for p in raw.split(",") if p.strip().isdigit()]
        else:
            ports = _COMMON_PORTS[:]

        # Nmap-like: sometimes sequential, sometimes random
        if random.random() > 0.4:
            random.shuffle(ports)
        return ports

    def _open_probability(self, port: int) -> float:
        """Typical open-port ratio for a real server."""
        if port in (22, 80, 443):
            return 0.85
        if port in (3306, 5432, 6379, 9200, 27017):
            return 0.3
        return 0.05

    # ------------------------------------------------------------------
    # SYN scan
    # ------------------------------------------------------------------

    def _syn_scan(self) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        ports = self._resolve_ports()
        timestamps = self._jittered_timestamps(len(ports), max_interval=0.05)

        for ts, port in zip(timestamps, ports):
            is_open = random.random() < self._open_probability(port)
            state = "OPEN" if is_open else random.choice(["RST_RECEIVED", "FILTERED", "TIMEOUT"])
            service = _SERVICES.get(port, "unknown")
            severity = "high" if is_open else "info"

            raw = (
                f"FIREWALL DROP: SYN {self.attacker_ip}:{random.randint(30000,65000)} "
                f"-> {self.target_ip}:{port} ({service}) STATE={state}"
            )
            logs.append(
                self._log_template(
                    offset_seconds=(ts - self.start_time).total_seconds(),
                    event_type="network_scan",
                    source_ip=self.attacker_ip,
                    dest_ip=self.target_ip,
                    hostname=self.target_host,
                    message=f"TCP SYN scan port {port}/{service} -> {state}",
                    severity=severity,
                    raw=raw,
                    protocol="tcp",
                    dest_port=port,
                    src_port=random.randint(30000, 65000),
                    connection_state=state,
                    service=service,
                    scan_type="syn",
                    port_open=is_open,
                    attack_vector="port_scan",
                )
            )

        return logs

    # ------------------------------------------------------------------
    # UDP scan
    # ------------------------------------------------------------------

    def _udp_scan(self) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        udp_ports = [53, 67, 68, 69, 111, 123, 137, 138, 161, 162, 500, 514, 520]
        random.shuffle(udp_ports)
        timestamps = self._jittered_timestamps(len(udp_ports), max_interval=0.5)

        for ts, port in zip(timestamps, udp_ports):
            state = random.choice(["OPEN|FILTERED", "CLOSED", "OPEN"])
            service = _SERVICES.get(port, "unknown")
            raw = (
                f"UDP {self.attacker_ip}:{random.randint(30000,65000)} "
                f"-> {self.target_ip}:{port} ({service}) STATE={state}"
            )
            logs.append(
                self._log_template(
                    offset_seconds=(ts - self.start_time).total_seconds(),
                    event_type="network_scan",
                    source_ip=self.attacker_ip,
                    dest_ip=self.target_ip,
                    hostname=self.target_host,
                    message=f"UDP scan port {port}/{service} -> {state}",
                    severity="medium" if "OPEN" in state else "info",
                    raw=raw,
                    protocol="udp",
                    dest_port=port,
                    src_port=random.randint(30000, 65000),
                    connection_state=state,
                    service=service,
                    scan_type="udp",
                    attack_vector="port_scan",
                )
            )

        return logs

    # ------------------------------------------------------------------
    # Version/service detection scan
    # ------------------------------------------------------------------

    def _version_scan(self) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        # First do a SYN scan to find open ports
        syn_logs = self._syn_scan()
        logs.extend(syn_logs)

        open_ports = [l["dest_port"] for l in syn_logs if l.get("port_open")]

        _banners = {
            22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
            80: "Apache/2.4.41 (Ubuntu)",
            443: "nginx/1.18.0",
            3306: "5.7.38-MySQL Community Server",
            5432: "PostgreSQL 14.5",
            6379: "Redis server v=7.0.5",
            3389: "Microsoft Terminal Services",
        }

        timestamps = self._jittered_timestamps(len(open_ports), max_interval=1.5)
        for ts, port in zip(timestamps, open_ports):
            banner = _banners.get(port, f"Service {_SERVICES.get(port,'unknown')} v1.0")
            raw = f"VERSION DETECTION: {self.target_ip}:{port} banner=\"{banner}\""
            logs.append(
                self._log_template(
                    offset_seconds=(ts - self.start_time).total_seconds() + 30,
                    event_type="service_discovery",
                    source_ip=self.attacker_ip,
                    dest_ip=self.target_ip,
                    hostname=self.target_host,
                    message=f"Service version detected on {port}: {banner}",
                    severity="high",
                    raw=raw,
                    protocol="tcp",
                    dest_port=port,
                    service_banner=banner,
                    scan_type="version",
                    attack_vector="port_scan",
                )
            )

        return logs

    # ------------------------------------------------------------------
    # Full TCP connect scan
    # ------------------------------------------------------------------

    def _full_connect_scan(self) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        ports = self._resolve_ports()
        timestamps = self._jittered_timestamps(len(ports), max_interval=0.15)

        for ts, port in zip(timestamps, ports):
            is_open = random.random() < self._open_probability(port)
            state = "ESTABLISHED" if is_open else "REFUSED"
            service = _SERVICES.get(port, "unknown")
            raw = (
                f"CONNECT {self.attacker_ip}:{random.randint(30000,65000)} "
                f"-> {self.target_ip}:{port} ({service}) {state}"
            )
            logs.append(
                self._log_template(
                    offset_seconds=(ts - self.start_time).total_seconds(),
                    event_type="network_scan",
                    source_ip=self.attacker_ip,
                    dest_ip=self.target_ip,
                    hostname=self.target_host,
                    message=f"Full connect scan port {port}/{service} -> {state}",
                    severity="high" if is_open else "info",
                    raw=raw,
                    protocol="tcp",
                    dest_port=port,
                    src_port=random.randint(30000, 65000),
                    connection_state=state,
                    service=service,
                    scan_type="full",
                    port_open=is_open,
                    attack_vector="port_scan",
                )
            )

        return logs
