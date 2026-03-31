"""Log normalizer – converts raw log lines/dicts to the unified SentinelMesh schema."""
from __future__ import annotations

import csv
import io
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog
from dateutil import parser as dateutil_parser

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Unified output schema
# ---------------------------------------------------------------------------


@dataclass
class NormalizedLog:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = ""
    source: str = ""
    source_type: str = "system"
    severity: str = "info"
    message: str = ""
    host: str = ""
    ip_address: str = ""
    user: str = ""
    process: str = ""
    event_type: str = ""
    raw_log: str = ""
    parsed_fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source": self.source,
            "source_type": self.source_type,
            "severity": self.severity,
            "message": self.message,
            "host": self.host,
            "ip_address": self.ip_address,
            "user": self.user,
            "process": self.process,
            "event_type": self.event_type,
            "raw_log": self.raw_log,
            "parsed_fields": self.parsed_fields,
        }


# ---------------------------------------------------------------------------
# Timestamp helper
# ---------------------------------------------------------------------------

_TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%d/%b/%Y:%H:%M:%S %z",      # Apache/Nginx
    "%b %d %H:%M:%S",            # RFC 3164 syslog
    "%b  %d %H:%M:%S",           # RFC 3164 – single-digit day
    "%Y %b %d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%d-%m-%Y %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%a %b %d %H:%M:%S %Z %Y",  # Unix ctime
    "%a, %d %b %Y %H:%M:%S %z",  # RFC 2822
    "%Y%m%d%H%M%S",
    "%Y%m%d",
    "%s",                         # unix epoch (handled separately)
]


def _parse_timestamp(ts_str: str) -> str:
    """Return an ISO-8601 UTC string from any of the supported formats."""
    if not ts_str:
        return datetime.now(timezone.utc).isoformat()

    # Unix epoch
    if re.fullmatch(r"\d{10}", ts_str):
        return datetime.fromtimestamp(int(ts_str), tz=timezone.utc).isoformat()
    if re.fullmatch(r"\d{13}", ts_str):
        return datetime.fromtimestamp(int(ts_str) / 1000, tz=timezone.utc).isoformat()

    for fmt in _TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            continue

    # Fall back to dateutil
    try:
        dt = dateutil_parser.parse(ts_str, fuzzy=True)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SYSLOG_SEVERITY: dict[int, str] = {
    0: "critical", 1: "critical", 2: "critical",
    3: "error", 4: "warning",
    5: "info", 6: "info", 7: "info",
}

_KEYWORD_SEVERITY: dict[str, str] = {
    "critical": "critical", "crit": "critical", "emerg": "critical", "alert": "critical",
    "error": "error", "err": "error", "failure": "error", "failed": "error",
    "warning": "warning", "warn": "warning",
    "notice": "info", "info": "info", "informational": "info", "debug": "info",
}


def _severity_from_keyword(kw: str) -> str:
    return _KEYWORD_SEVERITY.get(kw.lower().strip(), "info")


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# RFC 3164: <PRI>Mon DD HH:MM:SS HOST PROCESS[PID]: MSG
_RE_RFC3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ts>[A-Z][a-z]{2}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s"
    r"(?P<proc>[^\[:]+?)(?:\[(?P<pid>\d+)\])?:\s"
    r"(?P<msg>.*)$",
    re.DOTALL,
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
_RE_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d+)\s"
    r"(?P<ts>\S+)\s"
    r"(?P<host>\S+)\s"
    r"(?P<app>\S+)\s"
    r"(?P<procid>\S+)\s"
    r"(?P<msgid>\S+)\s"
    r"(?P<sd>-|\[.*?\])\s?"
    r"(?P<msg>.*)$",
    re.DOTALL,
)

# Apache / Nginx combined log format
_RE_APACHE = re.compile(
    r'^(?P<ip>\S+)\s\S+\s(?P<user>\S+)\s'
    r'\[(?P<ts>[^\]]+)\]\s'
    r'"(?P<method>\S+)\s(?P<path>\S+)\s(?P<proto>[^"]+)"\s'
    r'(?P<status>\d{3})\s(?P<bytes>\S+)'
    r'(?:\s"(?P<referer>[^"]*)"\s"(?P<ua>[^"]*)")?'
)

# CEF: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
_RE_CEF = re.compile(
    r"^CEF:(?P<cef_ver>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
    r"(?P<dev_ver>[^|]*)\|(?P<sig>[^|]*)\|(?P<name>[^|]*)\|(?P<sev>[^|]*)\|"
    r"(?P<ext>.*)$",
    re.DOTALL,
)

# Windows Event Log (plain-text representation)
_RE_WINEVT = re.compile(
    r"(?:EventID|Event ID)[:\s]+(?P<event_id>\d+)",
    re.IGNORECASE,
)

_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_USER = re.compile(r"(?:user|username|User)[=:\s]+(\S+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# LogNormalizer
# ---------------------------------------------------------------------------


class LogNormalizer:
    """Normalize raw log strings/dicts to the unified SentinelMesh schema."""

    def __init__(self, default_source: str = "unknown", default_source_type: str = "system") -> None:
        self.default_source = default_source
        self.default_source_type = default_source_type
        self._log = logger.bind(component="LogNormalizer")

    # ------------------------------------------------------------------
    # Public entry-points
    # ------------------------------------------------------------------

    def normalize(self, raw: str | dict[str, Any], source: str = "", source_type: str = "") -> NormalizedLog:
        """Auto-detect format and normalise *raw* to :class:`NormalizedLog`."""
        src = source or self.default_source
        stype = source_type or self.default_source_type

        if isinstance(raw, dict):
            return self.normalize_json(raw, src, stype)

        raw_str = str(raw).strip()

        if raw_str.startswith("CEF:"):
            return self.normalize_cef(raw_str, src, stype)
        if _RE_RFC5424.match(raw_str):
            return self.normalize_rfc5424(raw_str, src, stype)
        if _RE_RFC3164.match(raw_str):
            return self.normalize_rfc3164(raw_str, src, stype)
        if _RE_APACHE.match(raw_str):
            return self.normalize_apache(raw_str, src, stype)
        if raw_str.startswith("{") and raw_str.endswith("}"):
            try:
                return self.normalize_json(json.loads(raw_str), src, stype)
            except json.JSONDecodeError:
                pass
        if "," in raw_str and "\n" not in raw_str:
            try:
                return self.normalize_csv_line(raw_str, src, stype)
            except Exception:
                pass

        return self.normalize_plaintext(raw_str, src, stype)

    # ------------------------------------------------------------------
    # Format-specific normalizers
    # ------------------------------------------------------------------

    def normalize_rfc3164(self, raw: str, source: str, source_type: str) -> NormalizedLog:
        m = _RE_RFC3164.match(raw)
        if not m:
            return self.normalize_plaintext(raw, source, source_type)

        pri = int(m.group("pri") or 13)
        severity = _SYSLOG_SEVERITY.get(pri & 0x07, "info")
        ts = _parse_timestamp(m.group("ts"))

        nlog = NormalizedLog(
            timestamp=ts,
            source=source or m.group("host"),
            source_type=source_type,
            severity=severity,
            message=m.group("msg"),
            host=m.group("host"),
            process=m.group("proc").strip(),
            event_type="syslog",
            raw_log=raw,
            parsed_fields={
                "pri": pri,
                "facility": pri >> 3,
                "severity_code": pri & 0x07,
                "pid": m.group("pid"),
            },
        )
        nlog.ip_address = _extract_ip(m.group("msg"))
        nlog.user = _extract_user(m.group("msg"))
        return nlog

    def normalize_rfc5424(self, raw: str, source: str, source_type: str) -> NormalizedLog:
        m = _RE_RFC5424.match(raw)
        if not m:
            return self.normalize_plaintext(raw, source, source_type)

        pri = int(m.group("pri"))
        severity = _SYSLOG_SEVERITY.get(pri & 0x07, "info")

        nlog = NormalizedLog(
            timestamp=_parse_timestamp(m.group("ts")),
            source=source or m.group("app"),
            source_type=source_type,
            severity=severity,
            message=m.group("msg"),
            host=m.group("host"),
            process=m.group("app"),
            event_type="syslog5424",
            raw_log=raw,
            parsed_fields={
                "pri": pri,
                "facility": pri >> 3,
                "severity_code": pri & 0x07,
                "version": m.group("version"),
                "procid": m.group("procid"),
                "msgid": m.group("msgid"),
                "structured_data": m.group("sd"),
            },
        )
        nlog.ip_address = _extract_ip(m.group("msg"))
        nlog.user = _extract_user(m.group("msg"))
        return nlog

    def normalize_windows_event(self, raw: dict[str, Any], source: str, source_type: str) -> NormalizedLog:
        ts = _parse_timestamp(str(raw.get("TimeCreated", raw.get("timestamp", ""))))
        event_id = str(raw.get("EventID", raw.get("Id", "")))
        level_raw = str(raw.get("Level", raw.get("level", "Information"))).lower()
        level_map = {
            "0": "critical", "1": "critical", "2": "error",
            "3": "warning", "4": "info", "5": "info",
            "critical": "critical", "error": "error",
            "warning": "warning", "information": "info", "verbose": "info",
        }
        severity = level_map.get(level_raw, "info")
        message = raw.get("Message", raw.get("message", raw.get("Description", "")))

        return NormalizedLog(
            timestamp=ts,
            source=source or raw.get("Channel", "windows"),
            source_type=source_type or "system",
            severity=severity,
            message=str(message),
            host=str(raw.get("Computer", raw.get("host", ""))),
            user=str(raw.get("SubjectUserName", raw.get("user", ""))),
            process=str(raw.get("ProcessName", raw.get("process", ""))),
            event_type=f"windows_event_{event_id}" if event_id else "windows_event",
            raw_log=json.dumps(raw),
            parsed_fields={
                "event_id": event_id,
                "provider": raw.get("ProviderName", ""),
                "channel": raw.get("Channel", ""),
                "task": raw.get("Task", ""),
                "keywords": raw.get("Keywords", ""),
            },
        )

    def normalize_json(self, raw: dict[str, Any], source: str, source_type: str) -> NormalizedLog:
        # Windows Event Log heuristic
        if "EventID" in raw or ("Level" in raw and "Computer" in raw):
            return self.normalize_windows_event(raw, source, source_type)

        ts_candidates = ("timestamp", "time", "ts", "@timestamp", "date", "datetime")
        ts_raw = next((str(raw[k]) for k in ts_candidates if k in raw), "")
        ts = _parse_timestamp(ts_raw)

        sev_raw = str(raw.get("severity", raw.get("level", raw.get("priority", "info"))))
        severity = _severity_from_keyword(sev_raw)

        message = str(raw.get("message", raw.get("msg", raw.get("log", raw.get("text", "")))))
        host = str(raw.get("host", raw.get("hostname", raw.get("computer", ""))))
        ip = str(raw.get("ip", raw.get("ip_address", raw.get("src_ip", raw.get("remote_addr", "")))))
        user = str(raw.get("user", raw.get("username", raw.get("user_name", ""))))
        process = str(raw.get("process", raw.get("process_name", raw.get("app", raw.get("application", "")))))
        event_type = str(raw.get("event_type", raw.get("type", raw.get("category", "json_log"))))

        if not ip:
            ip = _extract_ip(message)
        if not user:
            user = _extract_user(message)

        return NormalizedLog(
            timestamp=ts,
            source=source or str(raw.get("source", "")),
            source_type=source_type,
            severity=severity,
            message=message,
            host=host,
            ip_address=ip,
            user=user,
            process=process,
            event_type=event_type,
            raw_log=json.dumps(raw),
            parsed_fields={k: v for k, v in raw.items() if k not in (
                "timestamp", "time", "ts", "@timestamp", "message", "msg",
                "severity", "level", "host", "hostname", "ip", "user",
            )},
        )

    def normalize_cef(self, raw: str, source: str, source_type: str) -> NormalizedLog:
        m = _RE_CEF.match(raw)
        if not m:
            return self.normalize_plaintext(raw, source, source_type)

        ext_raw = m.group("ext")
        ext: dict[str, str] = {}
        for pair in re.findall(r'(\w+)=([^ ]+(?:\s+(?!\w+=)[^ ]+)*)', ext_raw):
            ext[pair[0]] = pair[1]

        cef_sev = int(m.group("sev") or 0)
        if cef_sev <= 3:
            severity = "info"
        elif cef_sev <= 6:
            severity = "warning"
        elif cef_sev <= 8:
            severity = "error"
        else:
            severity = "critical"

        ts = _parse_timestamp(ext.get("rt", ext.get("start", ext.get("end", ""))))

        return NormalizedLog(
            timestamp=ts,
            source=source or f"{m.group('vendor')}/{m.group('product')}",
            source_type=source_type or "network",
            severity=severity,
            message=m.group("name"),
            host=ext.get("dhost", ext.get("shost", "")),
            ip_address=ext.get("dst", ext.get("src", "")),
            user=ext.get("duser", ext.get("suser", "")),
            process=ext.get("app", ""),
            event_type=f"cef_{m.group('sig')}",
            raw_log=raw,
            parsed_fields={
                "vendor": m.group("vendor"),
                "product": m.group("product"),
                "device_version": m.group("dev_ver"),
                "signature_id": m.group("sig"),
                "cef_version": m.group("cef_ver"),
                "cef_severity": cef_sev,
                "extension": ext,
            },
        )

    def normalize_apache(self, raw: str, source: str, source_type: str) -> NormalizedLog:
        m = _RE_APACHE.match(raw)
        if not m:
            return self.normalize_plaintext(raw, source, source_type)

        status = int(m.group("status"))
        if status >= 500:
            severity = "error"
        elif status >= 400:
            severity = "warning"
        else:
            severity = "info"

        return NormalizedLog(
            timestamp=_parse_timestamp(m.group("ts")),
            source=source or "web",
            source_type=source_type or "application",
            severity=severity,
            message=f"{m.group('method')} {m.group('path')} {status}",
            ip_address=m.group("ip"),
            user=m.group("user") if m.group("user") != "-" else "",
            event_type="http_access",
            raw_log=raw,
            parsed_fields={
                "method": m.group("method"),
                "path": m.group("path"),
                "protocol": m.group("proto"),
                "status_code": status,
                "bytes": m.group("bytes"),
                "referer": m.group("referer") or "",
                "user_agent": m.group("ua") or "",
            },
        )

    def normalize_csv_line(self, raw: str, source: str, source_type: str) -> NormalizedLog:
        reader = csv.reader(io.StringIO(raw))
        row = next(reader)
        fields: dict[str, str] = {f"field_{i}": v for i, v in enumerate(row)}

        # Attempt to auto-detect common positions
        ts = _parse_timestamp(row[0]) if row else datetime.now(timezone.utc).isoformat()
        message = row[1] if len(row) > 1 else raw

        return NormalizedLog(
            timestamp=ts,
            source=source,
            source_type=source_type,
            severity="info",
            message=message,
            event_type="csv_log",
            raw_log=raw,
            parsed_fields=fields,
        )

    def normalize_plaintext(self, raw: str, source: str, source_type: str) -> NormalizedLog:
        """Fallback normalizer for unrecognised plain-text log lines."""
        ts = _parse_timestamp(_extract_timestamp_heuristic(raw))
        severity = _detect_severity_keyword(raw)
        ip = _extract_ip(raw)
        user = _extract_user(raw)

        return NormalizedLog(
            timestamp=ts,
            source=source,
            source_type=source_type,
            severity=severity,
            message=raw[:2000],
            ip_address=ip,
            user=user,
            event_type="plaintext_log",
            raw_log=raw,
        )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _extract_ip(text: str) -> str:
    m = _RE_IP.search(text)
    return m.group(0) if m else ""


def _extract_user(text: str) -> str:
    m = _RE_USER.search(text)
    return m.group(1) if m else ""


def _extract_timestamp_heuristic(text: str) -> str:
    """Try to find an ISO-8601 or common timestamp at the beginning of *text*."""
    iso = re.match(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)", text)
    if iso:
        return iso.group(1)
    syslog = re.match(r"([A-Z][a-z]{2}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2})", text)
    if syslog:
        return syslog.group(1)
    return ""


def _detect_severity_keyword(text: str) -> str:
    lower = text.lower()
    for kw, sev in sorted(_KEYWORD_SEVERITY.items(), key=lambda x: len(x[0]), reverse=True):
        if kw in lower:
            return sev
    return "info"
