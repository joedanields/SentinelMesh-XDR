"""Real-time synthetic log stream ingester for SentinelMesh XDR."""
from __future__ import annotations

import asyncio
import json
import random
import time
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import structlog
from faker import Faker

from .base_ingester import AbstractIngester, RetryConfig
from .normalizer import LogNormalizer

logger = structlog.get_logger(__name__)
_faker = Faker()

# ---------------------------------------------------------------------------
# Synthetic log event generators
# ---------------------------------------------------------------------------

_SSH_USERS = ["root", "admin", "ubuntu", "ec2-user", "deploy", "git", "postgres", "hadoop"]
_PROCESSES = ["sshd", "nginx", "apache2", "postgres", "systemd", "kernel", "cron", "docker"]
_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
_HTTP_PATHS = [
    "/api/v1/users", "/api/v1/auth/login", "/api/v1/alerts", "/admin/",
    "/wp-admin/", "/.env", "/etc/passwd", "/api/v1/logs", "/health",
    "/../../../etc/shadow", "/api/v1/incidents", "/static/app.js",
]
_DNS_DOMAINS = [
    "google.com", "github.com", "evil-c2-server.xyz", "update.microsoft.com",
    "malware-domain.ru", "cdn.cloudflare.com", "pastebin.com", "raw.githubusercontent.com",
    "suspicious-exfil.net", "api.stripe.com",
]
_FIREWALL_ACTIONS = ["ACCEPT", "DROP", "REJECT", "FORWARD"]
_PROTOCOLS = ["TCP", "UDP", "ICMP"]
_WIN_EVENT_IDS = [4624, 4625, 4634, 4648, 4672, 4688, 4697, 4720, 4726, 4768, 4769, 4776]


def _rand_ip() -> str:
    return _faker.ipv4()


def _rand_internal_ip() -> str:
    return f"192.168.{random.randint(1, 10)}.{random.randint(2, 254)}"


def _ts_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------

class EventGenerator:
    """Generates realistic synthetic log events for various log sources."""

    @staticmethod
    def ssh_login() -> dict[str, Any]:
        success = random.random() > 0.3
        user = random.choice(_SSH_USERS)
        ip = _rand_ip()
        port = random.randint(49152, 65535)
        if success:
            msg = (
                f"Accepted {'publickey' if random.random() > 0.5 else 'password'} "
                f"for {user} from {ip} port {port} ssh2"
            )
            severity = "info"
        else:
            msg = f"Failed password for {'invalid user ' if random.random() > 0.5 else ''}{user} from {ip} port {port} ssh2"
            severity = "warning"
        return {
            "timestamp": _ts_now(),
            "source": "sshd",
            "source_type": "system",
            "severity": severity,
            "message": msg,
            "host": _faker.hostname(),
            "ip_address": ip,
            "user": user,
            "process": "sshd",
            "event_type": "ssh_login_success" if success else "ssh_login_failure",
            "parsed_fields": {"port": port, "auth_method": "publickey" if success else "password"},
        }

    @staticmethod
    def http_request() -> dict[str, Any]:
        ip = _rand_ip()
        method = random.choice(_HTTP_METHODS)
        path = random.choice(_HTTP_PATHS)
        # Skew toward suspicious paths occasionally
        if random.random() < 0.1:
            path = random.choice(["/.env", "/etc/passwd", "/../../../etc/shadow", "/wp-admin/"])
        status_weights = [200, 200, 200, 200, 301, 302, 400, 401, 403, 404, 500, 502]
        status = random.choice(status_weights)
        severity = "error" if status >= 500 else ("warning" if status >= 400 else "info")
        return {
            "timestamp": _ts_now(),
            "source": "nginx",
            "source_type": "application",
            "severity": severity,
            "message": f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                       f'"{method} {path} HTTP/1.1" {status} {random.randint(200, 50000)}',
            "ip_address": ip,
            "event_type": "http_request",
            "parsed_fields": {
                "method": method, "path": path, "status_code": status,
                "user_agent": _faker.user_agent(), "referer": "",
            },
        }

    @staticmethod
    def dns_query() -> dict[str, Any]:
        domain = random.choice(_DNS_DOMAINS)
        client = _rand_internal_ip()
        suspicious = domain in ("evil-c2-server.xyz", "malware-domain.ru", "suspicious-exfil.net")
        return {
            "timestamp": _ts_now(),
            "source": "bind9",
            "source_type": "network",
            "severity": "warning" if suspicious else "info",
            "message": f"client {client}#53: query: {domain} IN A +",
            "ip_address": client,
            "event_type": "dns_query",
            "parsed_fields": {
                "query_type": "A", "domain": domain,
                "client": client, "suspicious": suspicious,
            },
        }

    @staticmethod
    def firewall_event() -> dict[str, Any]:
        action = random.choice(_FIREWALL_ACTIONS)
        src_ip = _rand_ip()
        dst_ip = _rand_internal_ip()
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([22, 80, 443, 3306, 5432, 6379, 8080, 8443, 3389])
        proto = random.choice(_PROTOCOLS)
        severity = "warning" if action in ("DROP", "REJECT") else "info"
        return {
            "timestamp": _ts_now(),
            "source": "firewall",
            "source_type": "network",
            "severity": severity,
            "message": (
                f"action={action} protocol={proto} src={src_ip}:{src_port} "
                f"dst={dst_ip}:{dst_port}"
            ),
            "ip_address": src_ip,
            "event_type": "firewall_event",
            "parsed_fields": {
                "action": action, "protocol": proto,
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
            },
        }

    @staticmethod
    def process_execution() -> dict[str, Any]:
        process = random.choice(
            ["bash", "sh", "python3", "curl", "wget", "nc", "nmap", "tcpdump",
             "crontab", "chmod", "chown", "sudo", "su", "passwd"]
        )
        user = random.choice(_SSH_USERS)
        pid = random.randint(1000, 65535)
        ppid = random.randint(1, 999)
        cmdline = f"{process} {_faker.file_path(depth=2)}"
        suspicious = process in ("nc", "nmap", "tcpdump", "wget", "curl")
        return {
            "timestamp": _ts_now(),
            "source": "auditd",
            "source_type": "system",
            "severity": "warning" if suspicious else "info",
            "message": f"type=EXECVE msg=audit: argc=2 a0={process!r} a1={cmdline!r}",
            "user": user,
            "process": process,
            "event_type": "process_execution",
            "parsed_fields": {
                "pid": pid, "ppid": ppid, "process": process,
                "cmdline": cmdline, "user": user, "suspicious": suspicious,
            },
        }

    @staticmethod
    def auth_event() -> dict[str, Any]:
        event_id = random.choice(_WIN_EVENT_IDS)
        user = random.choice(_SSH_USERS)
        ip = _rand_ip()
        event_names = {
            4624: "An account was successfully logged on",
            4625: "An account failed to log on",
            4634: "An account was logged off",
            4648: "A logon was attempted using explicit credentials",
            4672: "Special privileges assigned to new logon",
            4688: "A new process has been created",
            4697: "A service was installed in the system",
            4720: "A user account was created",
            4726: "A user account was deleted",
            4768: "A Kerberos authentication ticket was requested",
            4769: "A Kerberos service ticket was requested",
            4776: "The computer attempted to validate the credentials for an account",
        }
        severity = "warning" if event_id in (4625, 4697, 4720, 4726) else "info"
        return {
            "timestamp": _ts_now(),
            "source": "Security",
            "source_type": "system",
            "severity": severity,
            "message": event_names.get(event_id, "Authentication event"),
            "host": _faker.hostname(),
            "ip_address": ip,
            "user": user,
            "event_type": f"windows_event_{event_id}",
            "parsed_fields": {
                "EventID": event_id,
                "SubjectUserName": user,
                "IpAddress": ip,
                "Channel": "Security",
            },
        }


_GENERATORS = [
    (EventGenerator.ssh_login, 20),
    (EventGenerator.http_request, 35),
    (EventGenerator.dns_query, 15),
    (EventGenerator.firewall_event, 15),
    (EventGenerator.process_execution, 10),
    (EventGenerator.auth_event, 5),
]
_GEN_FUNCS, _GEN_WEIGHTS = zip(*_GENERATORS)


# ---------------------------------------------------------------------------
# StreamIngester
# ---------------------------------------------------------------------------


class StreamIngester(AbstractIngester):
    """Generates synthetic real-time log events and streams them.

    Features
    --------
    * Configurable events/second rate.
    * Weighted selection across 6 realistic event types.
    * Internal asyncio.Queue – consumers call :meth:`ingest` or iterate
      via :meth:`stream`.
    * WebSocket-friendly: supports async generator interface.
    * Buffer back-pressure: drops events when queue is full and logs a metric.
    """

    def __init__(
        self,
        source_name: str = "synthetic_stream",
        events_per_second: float = 10.0,
        batch_size: int = 100,
        queue_maxsize: int = 50_000,
        retry_config: RetryConfig | None = None,
    ) -> None:
        super().__init__(
            source_name=source_name,
            source_type="stream",
            batch_size=batch_size,
            retry_config=retry_config,
        )
        self.events_per_second = max(0.1, events_per_second)
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_maxsize)
        self._producer_task: asyncio.Task | None = None
        self._log = logger.bind(ingester="StreamIngester", source=source_name)

    # ------------------------------------------------------------------
    # AbstractIngester interface
    # ------------------------------------------------------------------

    async def ingest(self) -> list[dict[str, Any]]:
        """Drain up to *batch_size* events from the internal queue."""
        batch: list[dict[str, Any]] = []
        deadline = asyncio.get_event_loop().time() + (self.batch_size / self.events_per_second + 0.1)

        while len(batch) < self.batch_size:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=min(remaining, 1.0))
                batch.append(item)
                self._queue.task_done()
            except asyncio.TimeoutError:
                break
        return batch

    def validate(self, raw: dict[str, Any]) -> bool:
        return "event_type" in raw and "timestamp" in raw

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Events from the generator are already semi-normalised."""
        raw.setdefault("id", str(uuid.uuid4()))
        raw.setdefault("source", self.source_name)
        raw.setdefault("raw_log", json.dumps(raw))
        return raw

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        await super().start()
        self._producer_task = asyncio.create_task(self._produce_loop(), name="stream_producer")

    async def stop(self) -> None:
        if self._producer_task:
            self._producer_task.cancel()
            try:
                await self._producer_task
            except asyncio.CancelledError:
                pass
        await super().stop()

    # ------------------------------------------------------------------
    # Streaming generator (WebSocket-compatible)
    # ------------------------------------------------------------------

    async def stream(self) -> AsyncIterator[dict[str, Any]]:
        """Async generator – yields events one at a time.  Suitable for
        direct consumption by a WebSocket handler."""
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                self._queue.task_done()
                yield event
            except asyncio.TimeoutError:
                continue

    # ------------------------------------------------------------------
    # Internal producer
    # ------------------------------------------------------------------

    async def _produce_loop(self) -> None:
        interval = 1.0 / self.events_per_second
        self._log.info("stream producer started", rate=self.events_per_second)

        while self._running:
            start = time.perf_counter()
            try:
                event = self._generate_event()
                if not self._queue.full():
                    await self._queue.put(event)
                    self.metrics.record_ingested()
                else:
                    self._log.debug("stream queue full – dropping event")
                    self.metrics.record_error("stream queue full")
            except Exception as exc:
                self._log.error("producer error", error=str(exc))
                self.metrics.record_error(str(exc))

            elapsed = time.perf_counter() - start
            sleep_time = max(0.0, interval - elapsed)
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

    def _generate_event(self) -> dict[str, Any]:
        gen_fn = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
        event = gen_fn()
        event["id"] = str(uuid.uuid4())
        event["raw_log"] = json.dumps(event)
        return event

    # ------------------------------------------------------------------
    # Rate control
    # ------------------------------------------------------------------

    def set_rate(self, events_per_second: float) -> None:
        """Adjust the event generation rate at runtime."""
        self.events_per_second = max(0.1, events_per_second)
        self._log.info("stream rate updated", new_rate=self.events_per_second)

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()
