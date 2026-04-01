"""Brute-force attack simulator (SSH, RDP, web login)."""

from __future__ import annotations

import random
from datetime import timedelta
from typing import Any, Dict, List, Optional

from .base_simulator import BaseSimulator, _rand_internal_ip, _rand_username


class BruteForceSimulator(BaseSimulator):
    """
    Simulates credential brute-force attacks.

    Supported attack vectors
    ------------------------
    * SSH brute force   → syslog-formatted auth failure / success lines
    * RDP brute force   → Windows Security Event Log style entries
    * Web login         → Apache/Nginx access log HTTP 401 / 200 lines
    """

    scenario_name = "brute_force"

    # Common username wordlists used in real attacks
    _DEFAULT_USERNAMES = [
        "admin", "root", "administrator", "user", "test", "guest",
        "ubuntu", "pi", "oracle", "postgres", "deploy", "jenkins",
    ]

    def __init__(
        self,
        *,
        target_host: Optional[str] = None,
        attacker_ip: Optional[str] = None,
        username_list: Optional[List[str]] = None,
        attempt_count: int = 150,
        success_rate: float = 0.005,
        attack_type: str = "ssh",
        start_time=None,
        seed: Optional[int] = None,
    ) -> None:
        super().__init__(
            target_host=target_host,
            attacker_ip=attacker_ip,
            start_time=start_time,
            seed=seed,
        )
        self.username_list = username_list or list(self._DEFAULT_USERNAMES)
        self.attempt_count = max(50, min(500, attempt_count))
        self.success_rate = max(0.0, min(1.0, success_rate))
        self.attack_type = attack_type.lower()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def simulate(self, **params: Any) -> List[Dict[str, Any]]:
        """Return the full list of simulated log events."""
        attack_type = params.get("attack_type", self.attack_type)
        dispatch = {
            "ssh": self._simulate_ssh,
            "rdp": self._simulate_rdp,
            "web": self._simulate_web,
        }
        fn = dispatch.get(attack_type, self._simulate_ssh)
        return fn()

    # ------------------------------------------------------------------
    # SSH brute force
    # ------------------------------------------------------------------

    def _simulate_ssh(self) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        timestamps = self._jittered_timestamps(self.attempt_count + 1, max_interval=4.0)
        successful_attempt = (
            random.randint(int(self.attempt_count * 0.8), self.attempt_count - 1)
            if self.success_rate > 0
            else None
        )
        successful_user = random.choice(self.username_list)
        src_port_base = random.randint(30000, 60000)

        for i, ts in enumerate(timestamps[: self.attempt_count]):
            username = random.choice(self.username_list)
            src_port = src_port_base + i
            is_success = successful_attempt is not None and i == successful_attempt

            if is_success:
                username = successful_user
                message = (
                    f"Accepted password for {username} from {self.attacker_ip} "
                    f"port {src_port} ssh2"
                )
                event_outcome = "success"
                severity = "warning"
            else:
                fail_reason = random.choice(
                    ["Failed password", "Invalid user", "Connection closed by authenticating user"]
                )
                message = (
                    f"{fail_reason} {username} from {self.attacker_ip} "
                    f"port {src_port} ssh2"
                )
                event_outcome = "failure"
                severity = "info"

            raw_syslog = self._syslog_line(ts, self.target_host, "sshd", message)
            logs.append(
                self._log_template(
                    offset_seconds=(ts - self.start_time).total_seconds(),
                    event_type="authentication",
                    source_ip=self.attacker_ip,
                    dest_ip=_rand_internal_ip(),
                    username=username,
                    hostname=self.target_host,
                    message=message,
                    severity=severity,
                    raw=raw_syslog,
                    protocol="ssh",
                    dest_port=22,
                    src_port=src_port,
                    event_outcome=event_outcome,
                    attack_vector="brute_force_ssh",
                    attempt_number=i + 1,
                )
            )

        # Append post-compromise activity after successful login
        if successful_attempt is not None:
            post_ts = timestamps[successful_attempt] + timedelta(seconds=random.uniform(5, 30))
            logs.append(
                self._log_template(
                    offset_seconds=(post_ts - self.start_time).total_seconds(),
                    event_type="process_execution",
                    source_ip=self.attacker_ip,
                    hostname=self.target_host,
                    username=successful_user,
                    message=f"New session opened for user {successful_user}",
                    severity="warning",
                    attack_vector="brute_force_ssh",
                    protocol="ssh",
                    dest_port=22,
                    post_compromise=True,
                )
            )
        return logs

    # ------------------------------------------------------------------
    # RDP brute force
    # ------------------------------------------------------------------

    def _simulate_rdp(self) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        timestamps = self._jittered_timestamps(self.attempt_count + 1, max_interval=6.0)
        successful_attempt = (
            random.randint(int(self.attempt_count * 0.7), self.attempt_count - 1)
            if self.success_rate > 0
            else None
        )
        successful_user = random.choice(self.username_list)

        for i, ts in enumerate(timestamps[: self.attempt_count]):
            username = random.choice(self.username_list)
            is_success = successful_attempt is not None and i == successful_attempt

            if is_success:
                username = successful_user
                event_id = 4624
                event_desc = "An account was successfully logged on"
                logon_type = 10  # RemoteInteractive
                severity = "warning"
                event_outcome = "success"
            else:
                event_id = 4625
                event_desc = "An account failed to log on"
                logon_type = 10
                severity = "info"
                event_outcome = "failure"

            message = (
                f"EventID={event_id} {event_desc}. "
                f"Account: {username}  LogonType: {logon_type}  "
                f"SourceIP: {self.attacker_ip}"
            )
            logs.append(
                self._log_template(
                    offset_seconds=(ts - self.start_time).total_seconds(),
                    event_type="authentication",
                    source_ip=self.attacker_ip,
                    dest_ip=_rand_internal_ip(),
                    username=username,
                    hostname=self.target_host,
                    message=message,
                    severity=severity,
                    protocol="rdp",
                    dest_port=3389,
                    event_id=event_id,
                    logon_type=logon_type,
                    event_outcome=event_outcome,
                    attack_vector="brute_force_rdp",
                    attempt_number=i + 1,
                )
            )

        return logs

    # ------------------------------------------------------------------
    # Web login brute force
    # ------------------------------------------------------------------

    def _simulate_web(self) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        timestamps = self._jittered_timestamps(self.attempt_count + 1, max_interval=3.0)
        paths = ["/login", "/admin/login", "/wp-login.php", "/api/v1/auth/login", "/signin"]
        login_path = random.choice(paths)
        user_agents = [
            "python-requests/2.28.0",
            "curl/7.88.1",
            "Mozilla/5.0 (compatible; Hydra)",
            "Medusa/2.2",
            "Go-http-client/1.1",
        ]
        ua = random.choice(user_agents)
        successful_attempt = (
            random.randint(int(self.attempt_count * 0.6), self.attempt_count - 1)
            if self.success_rate > 0
            else None
        )
        successful_user = random.choice(self.username_list)

        for i, ts in enumerate(timestamps[: self.attempt_count]):
            username = random.choice(self.username_list)
            is_success = successful_attempt is not None and i == successful_attempt

            if is_success:
                username = successful_user
                status_code = 200
                severity = "warning"
                event_outcome = "success"
                bytes_sent = random.randint(800, 2500)
            else:
                status_code = 401
                severity = "info"
                event_outcome = "failure"
                bytes_sent = random.randint(300, 600)

            ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
            raw_access = (
                f'{self.attacker_ip} - {username} [{ts_str}] '
                f'"POST {login_path} HTTP/1.1" {status_code} {bytes_sent} '
                f'"-" "{ua}"'
            )
            message = f"HTTP {status_code} POST {login_path} from {self.attacker_ip}"
            logs.append(
                self._log_template(
                    offset_seconds=(ts - self.start_time).total_seconds(),
                    event_type="web_auth",
                    source_ip=self.attacker_ip,
                    dest_ip=_rand_internal_ip(),
                    username=username,
                    hostname=self.target_host,
                    message=message,
                    severity=severity,
                    raw=raw_access,
                    protocol="http",
                    dest_port=443 if random.random() > 0.3 else 80,
                    http_method="POST",
                    http_path=login_path,
                    http_status=status_code,
                    bytes_sent=bytes_sent,
                    user_agent=ua,
                    event_outcome=event_outcome,
                    attack_vector="brute_force_web",
                    attempt_number=i + 1,
                )
            )

        return logs
