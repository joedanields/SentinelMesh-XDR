"""Data exfiltration attack simulator."""

from __future__ import annotations

import random
import string
from typing import Any, Dict, List, Optional

from .base_simulator import BaseSimulator, _rand_external_ip, _rand_internal_ip


# ---------------------------------------------------------------------------
# Data pools
# ---------------------------------------------------------------------------

_SENSITIVE_FILE_PATTERNS = [
    "employees_pii.csv", "customer_data_2024.xlsx", "financial_report_Q3.pdf",
    "passwords.kdbx", "vpn_config.ovpn", "database_dump.sql.gz",
    "source_code.tar.gz", "intellectual_property.zip", "ssl_certificates.tar",
    "aws_credentials.json", "service_account_keys.json", "id_rsa",
]

_EXFIL_DOMAINS = [
    "file-share-temp.com", "pastebin-upload.net", "cloud-sync-secure.io",
    "backup-service-247.com", "cdn-assets-global.net", "update-server-cdn.io",
]

_DNS_SUBDOMAIN_CHARS = string.ascii_lowercase + string.digits

_HTTP_ENDPOINTS = [
    "/api/upload", "/submit", "/data", "/sync", "/upload.php",
    "/collect", "/beacon", "/exfil", "/out",
]

_PROTOCOLS = ["https", "http", "dns", "ftp", "icmp"]


def _rand_dns_subdomain(length: int = 40) -> str:
    """Generate a long random subdomain as used in DNS exfiltration."""
    return "".join(random.choices(_DNS_SUBDOMAIN_CHARS, k=length))


class DataExfiltrationSimulator(BaseSimulator):
    """
    Simulates data exfiltration events.

    Exfiltration channels
    ---------------------
    * Large HTTPS/HTTP POST transfers to external IPs
    * DNS tunnel (unusually long subdomains carrying encoded data)
    * FTP upload to external server
    * ICMP tunnelling (large payloads)
    * File access sweep before exfiltration
    """

    scenario_name = "data_exfiltration"

    def __init__(
        self,
        *,
        source_host: Optional[str] = None,
        attacker_ip: Optional[str] = None,
        exfil_channel: str = "https",
        data_volume_mb: float = 50.0,
        start_time=None,
        seed: Optional[int] = None,
    ) -> None:
        super().__init__(
            target_host=source_host,
            attacker_ip=attacker_ip,
            start_time=start_time,
            seed=seed,
        )
        self.source_host = self.target_host
        self.exfil_dest = _rand_external_ip()
        self.exfil_channel = exfil_channel.lower()
        self.data_volume_mb = max(1.0, data_volume_mb)

    # ------------------------------------------------------------------

    def simulate(self, **params: Any) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        offset = 0.0

        # Phase 1: file reconnaissance / access sweep
        logs.extend(self._file_access_sweep(offset))
        offset += random.uniform(60, 300)

        # Phase 2: staging (compress / archive)
        logs.extend(self._staging_activity(offset))
        offset += random.uniform(30, 120)

        # Phase 3: actual exfiltration via chosen channel
        channel_fn = {
            "https": self._https_exfiltration,
            "http": self._https_exfiltration,
            "dns": self._dns_exfiltration,
            "ftp": self._ftp_exfiltration,
            "icmp": self._icmp_exfiltration,
        }.get(self.exfil_channel, self._https_exfiltration)

        logs.extend(channel_fn(offset))

        return sorted(logs, key=lambda x: x["timestamp"])

    # ------------------------------------------------------------------
    # Phase 1 – file access sweep
    # ------------------------------------------------------------------

    def _file_access_sweep(self, base_offset: float) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        timestamps = self._jittered_timestamps(len(_SENSITIVE_FILE_PATTERNS), max_interval=8)

        for ts, filename in zip(timestamps, _SENSITIVE_FILE_PATTERNS):
            off = base_offset + (ts - self.start_time).total_seconds()
            size_kb = random.randint(50, 50_000)
            logs.append(
                self._log_template(
                    offset_seconds=off,
                    event_type="file_access",
                    source_ip=_rand_internal_ip(),
                    dest_ip=_rand_internal_ip(),
                    hostname=self.source_host,
                    message=f"Sensitive file accessed: {filename} ({size_kb} KB)",
                    severity="high",
                    filename=filename,
                    file_size_kb=size_kb,
                    operation="read",
                    attack_vector="data_exfiltration",
                    phase="reconnaissance",
                )
            )

        return logs

    # ------------------------------------------------------------------
    # Phase 2 – staging
    # ------------------------------------------------------------------

    def _staging_activity(self, base_offset: float) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        staging_dir = random.choice([
            r"C:\Windows\Temp\update_cache",
            "/tmp/.hidden_dir",
            r"C:\ProgramData\Microsoft\crypto",
        ])
        archive_name = f"data_{self._random_string(6)}.7z"
        timestamps = self._jittered_timestamps(3, max_interval=20)
        events = [
            (
                "process_execution",
                f"7z.exe a -mx9 {staging_dir}\\{archive_name} C:\\Users\\*",
                "critical",
            ),
            (
                "process_execution",
                f"certutil -encode {staging_dir}\\{archive_name} {staging_dir}\\out.b64",
                "critical",
            ),
            (
                "file_write",
                f"Staged archive created: {staging_dir}\\{archive_name} ({self.data_volume_mb:.0f} MB)",
                "high",
            ),
        ]
        for ts, (ev, msg, sev) in zip(timestamps, events):
            off = base_offset + (ts - self.start_time).total_seconds()
            logs.append(
                self._log_template(
                    offset_seconds=off,
                    event_type=ev,
                    source_ip=_rand_internal_ip(),
                    dest_ip=_rand_internal_ip(),
                    hostname=self.source_host,
                    message=msg,
                    severity=sev,
                    staging_dir=staging_dir,
                    archive_name=archive_name,
                    attack_vector="data_exfiltration",
                    phase="staging",
                )
            )

        return logs

    # ------------------------------------------------------------------
    # Phase 3 – HTTPS exfiltration
    # ------------------------------------------------------------------

    def _https_exfiltration(self, base_offset: float) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        chunk_size_mb = random.uniform(1, 5)
        num_chunks = max(1, int(self.data_volume_mb / chunk_size_mb))
        timestamps = self._jittered_timestamps(num_chunks, max_interval=15)
        endpoint = random.choice(_HTTP_ENDPOINTS)
        dest_domain = random.choice(_EXFIL_DOMAINS)
        port = 443 if self.exfil_channel == "https" else 80

        total_sent = 0.0
        for i, ts in enumerate(timestamps):
            off = base_offset + (ts - self.start_time).total_seconds()
            chunk_bytes = int(chunk_size_mb * 1024 * 1024 * random.uniform(0.8, 1.2))
            total_sent += chunk_bytes / (1024 * 1024)
            logs.append(
                self._log_template(
                    offset_seconds=off,
                    event_type="network_flow",
                    source_ip=_rand_internal_ip(),
                    dest_ip=self.exfil_dest,
                    hostname=self.source_host,
                    message=(
                        f"Large outbound {self.exfil_channel.upper()} transfer "
                        f"to {self.exfil_dest}:{port} "
                        f"({chunk_bytes / 1024:.0f} KB) chunk {i+1}/{num_chunks}"
                    ),
                    severity="critical",
                    protocol=self.exfil_channel,
                    dest_port=port,
                    dest_domain=dest_domain,
                    http_path=endpoint,
                    http_method="POST",
                    bytes_sent=chunk_bytes,
                    bytes_recv=random.randint(100, 500),
                    chunk_number=i + 1,
                    total_chunks=num_chunks,
                    cumulative_mb=round(total_sent, 2),
                    attack_vector="data_exfiltration",
                    phase="exfiltration",
                    mitre_technique="T1041",
                )
            )

        return logs

    # ------------------------------------------------------------------
    # Phase 3 – DNS exfiltration
    # ------------------------------------------------------------------

    def _dns_exfiltration(self, base_offset: float) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        # Estimate: ~60 bytes per query (base32-encoded chunk)
        num_queries = max(10, int(self.data_volume_mb * 1024 * 1024 / 60))
        num_queries = min(num_queries, 500)  # cap for simulation
        timestamps = self._jittered_timestamps(num_queries, max_interval=0.5)
        c2_domain = random.choice(_EXFIL_DOMAINS)

        for i, ts in enumerate(timestamps):
            off = base_offset + (ts - self.start_time).total_seconds()
            subdomain = _rand_dns_subdomain(random.randint(35, 62))
            fqdn = f"{subdomain}.{c2_domain}"
            logs.append(
                self._log_template(
                    offset_seconds=off,
                    event_type="dns_query",
                    source_ip=_rand_internal_ip(),
                    dest_ip="8.8.8.8",
                    hostname=self.source_host,
                    message=f"Suspicious DNS query: {fqdn} (subdomain length={len(subdomain)})",
                    severity="high" if len(subdomain) > 50 else "medium",
                    protocol="dns",
                    dest_port=53,
                    query_name=fqdn,
                    query_type="A",
                    subdomain_length=len(subdomain),
                    c2_domain=c2_domain,
                    query_number=i + 1,
                    attack_vector="data_exfiltration",
                    phase="exfiltration",
                    mitre_technique="T1048.003",
                )
            )

        return logs

    # ------------------------------------------------------------------
    # Phase 3 – FTP exfiltration
    # ------------------------------------------------------------------

    def _ftp_exfiltration(self, base_offset: float) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        timestamps = self._jittered_timestamps(5, max_interval=30)
        ftp_events = [
            (f"FTP CONNECT {self.source_host} -> {self.exfil_dest}:21", "network_connection", "high"),
            (f"FTP LOGIN anonymous@{self.exfil_dest}", "authentication", "high"),
            (f"FTP STOR data_dump.tar.gz ({self.data_volume_mb:.0f} MB)", "file_transfer", "critical"),
            (f"FTP transfer complete: {self.data_volume_mb:.0f} MB in {random.randint(30,300)}s", "file_transfer", "critical"),
            (f"FTP QUIT {self.exfil_dest}", "network_connection", "medium"),
        ]
        for ts, (msg, ev, sev) in zip(timestamps, ftp_events):
            off = base_offset + (ts - self.start_time).total_seconds()
            logs.append(
                self._log_template(
                    offset_seconds=off,
                    event_type=ev,
                    source_ip=_rand_internal_ip(),
                    dest_ip=self.exfil_dest,
                    hostname=self.source_host,
                    message=msg,
                    severity=sev,
                    protocol="ftp",
                    dest_port=21,
                    bytes_sent=int(self.data_volume_mb * 1024 * 1024),
                    attack_vector="data_exfiltration",
                    phase="exfiltration",
                    mitre_technique="T1048.003",
                )
            )
        return logs

    # ------------------------------------------------------------------
    # Phase 3 – ICMP exfiltration
    # ------------------------------------------------------------------

    def _icmp_exfiltration(self, base_offset: float) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        num_packets = min(200, max(20, int(self.data_volume_mb * 100)))
        timestamps = self._jittered_timestamps(num_packets, max_interval=0.3)

        for i, ts in enumerate(timestamps):
            off = base_offset + (ts - self.start_time).total_seconds()
            payload_size = random.randint(800, 1480)  # Abnormally large ICMP
            logs.append(
                self._log_template(
                    offset_seconds=off,
                    event_type="network_flow",
                    source_ip=_rand_internal_ip(),
                    dest_ip=self.exfil_dest,
                    hostname=self.source_host,
                    message=(
                        f"Large ICMP echo request to {self.exfil_dest} "
                        f"payload={payload_size}B (expected ≤64B)"
                    ),
                    severity="high",
                    protocol="icmp",
                    icmp_type=8,
                    payload_bytes=payload_size,
                    packet_number=i + 1,
                    attack_vector="data_exfiltration",
                    phase="exfiltration",
                    mitre_technique="T1048.003",
                )
            )
        return logs
