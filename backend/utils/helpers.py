"""General-purpose utility helpers for SentinelMesh XDR."""
from __future__ import annotations

import csv
import io
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional


# ---------------------------------------------------------------------------
# UUID / identity
# ---------------------------------------------------------------------------


def generate_uuid() -> str:
    """Return a new random UUID string."""
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Timestamp normalisation
# ---------------------------------------------------------------------------

_ISO_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
)


def normalize_timestamp(ts: Any) -> datetime:
    """Convert various timestamp representations to a Python :class:`datetime`.

    Handles:
    * ``datetime`` – returned as-is.
    * ``int`` / ``float`` – treated as a Unix epoch (seconds).
    * ``str`` – tried against common ISO formats, then against
      *python-dateutil* for anything unusual.
    """
    if isinstance(ts, datetime):
        return ts

    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)

    if isinstance(ts, str):
        ts_stripped = ts.strip()
        for fmt in _ISO_FORMATS:
            try:
                return datetime.strptime(ts_stripped, fmt)
            except ValueError:
                continue
        # Fall back to dateutil for ambiguous formats
        try:
            from dateutil import parser as du_parser
            return du_parser.parse(ts_stripped)
        except Exception as exc:
            raise ValueError(f"Cannot parse timestamp: {ts!r}") from exc

    raise TypeError(f"Unsupported timestamp type: {type(ts).__name__}")


# ---------------------------------------------------------------------------
# IP extraction
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
    r"|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b"
    r"|\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b"
    r"|\b::(?:[fF]{4}(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}"
    r"(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\b"
)


def extract_ip_from_log(log_text: str) -> Optional[str]:
    """Return the first IPv4 or IPv6 address found in *log_text*, or ``None``."""
    m = _IPV4_RE.search(log_text)
    if m:
        return m.group(0)
    m = _IPV6_RE.search(log_text)
    if m:
        return m.group(0)
    return None


# ---------------------------------------------------------------------------
# Risk score calculation
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    # Also accept info / warning / error for compatibility
    "info": 0.1,
    "warning": 0.35,
    "error": 0.65,
}


def calculate_risk_score(
    severity: str,
    confidence: float,
    asset_criticality: float = 1.0,
) -> float:
    """Return a normalised risk score in the range [0, 100].

    Formula: ``severity_weight * confidence * asset_criticality * 100``.
    """
    weight = _SEVERITY_WEIGHTS.get(severity.lower(), 0.5)
    score = weight * confidence * asset_criticality * 100.0
    return max(0.0, min(100.0, score))


# ---------------------------------------------------------------------------
# Data sanitisation
# ---------------------------------------------------------------------------

_SENSITIVE_KEYS = frozenset(
    {"password", "token", "secret", "key", "credential", "auth", "api_key", "apikey",
     "private_key", "access_token", "refresh_token", "client_secret"}
)


def sanitize_log_data(data: dict) -> dict:
    """Return a deep copy of *data* with sensitive field values replaced by ``"[REDACTED]"``."""
    sanitized: dict = {}
    for k, v in data.items():
        if any(sensitive in k.lower() for sensitive in _SENSITIVE_KEYS):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_log_data(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_log_data(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized


# ---------------------------------------------------------------------------
# String / byte helpers
# ---------------------------------------------------------------------------

_BYTE_UNITS = ("B", "KB", "MB", "GB", "TB")


def format_bytes(size_bytes: int) -> str:
    """Return a human-readable file-size string, e.g. ``"1.23 MB"``."""
    if size_bytes < 0:
        raise ValueError("size_bytes must be non-negative")
    if size_bytes == 0:
        return "0 B"
    magnitude = size_bytes
    for unit in _BYTE_UNITS:
        if magnitude < 1024:
            return f"{magnitude:.2f} {unit}" if unit != "B" else f"{magnitude} {unit}"
        magnitude /= 1024
    return f"{magnitude:.2f} TB"


def truncate_string(s: str, max_length: int = 255, suffix: str = "...") -> str:
    """Truncate *s* to *max_length* characters, appending *suffix* if truncated."""
    if len(s) <= max_length:
        return s
    return s[: max_length - len(suffix)] + suffix


# ---------------------------------------------------------------------------
# Dict helpers
# ---------------------------------------------------------------------------


def deep_merge_dicts(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*.  *override* wins on conflicts."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def flatten_dict(d: dict, parent_key: str = "", sep: str = ".") -> dict:
    """Flatten a nested dictionary using dot-notation keys."""
    items: list[tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


# ---------------------------------------------------------------------------
# Log line parsing
# ---------------------------------------------------------------------------

# Syslog RFC-3164: "<PRI>Mon  1 00:00:00 hostname app[pid]: message"
_SYSLOG_RE = re.compile(
    r"^<(?P<priority>\d+)>"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

# CEF: "CEF:version|vendor|product|device_version|signatureId|name|severity|extensions"
_CEF_PREFIX_RE = re.compile(r"^CEF:(?P<version>\d+)\|", re.IGNORECASE)


def _parse_cef(line: str) -> Optional[dict]:
    """Parse a Common Event Format (CEF) log line."""
    match = _CEF_PREFIX_RE.match(line)
    if not match:
        return None
    parts = line.split("|", 8)
    if len(parts) < 8:
        return None
    extensions: dict = {}
    ext_str = parts[7].strip() if len(parts) > 7 else ""
    # CEF extensions: key=value pairs, values may be escaped
    ext_pattern = re.compile(r"(\w+)=((?:[^\\=\s]|\\.)+(?:\s+(?!\w+=)(?:[^\\=\s]|\\.)+)*)")
    for m in ext_pattern.finditer(ext_str):
        extensions[m.group(1)] = m.group(2).replace(r"\=", "=").replace(r"\\", "\\")
    return {
        "format": "cef",
        "cef_version": match.group("version"),
        "device_vendor": parts[1],
        "device_product": parts[2],
        "device_version": parts[3],
        "signature_id": parts[4],
        "name": parts[5],
        "severity": parts[6],
        "extensions": extensions,
    }


def _parse_syslog(line: str) -> Optional[dict]:
    """Parse an RFC-3164 syslog line."""
    m = _SYSLOG_RE.match(line.strip())
    if not m:
        return None
    return {
        "format": "syslog",
        "priority": int(m.group("priority")),
        "timestamp": m.group("timestamp"),
        "hostname": m.group("hostname"),
        "app": m.group("app"),
        "pid": m.group("pid"),
        "message": m.group("message"),
    }


def parse_log_line(line: str) -> dict:
    """Parse a raw log line and return a structured dictionary.

    Detection order:
    1. JSON
    2. CEF (Common Event Format)
    3. Syslog (RFC-3164)
    4. CSV (comma-separated – first row treated as headers if present)
    5. Fallback: ``{"format": "unknown", "raw": line}``
    """
    stripped = line.strip()

    # 1. JSON
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                parsed.setdefault("format", "json")
                return parsed
            return {"format": "json", "data": parsed}
        except json.JSONDecodeError:
            pass

    # 2. CEF
    cef = _parse_cef(stripped)
    if cef is not None:
        return cef

    # 3. Syslog
    syslog = _parse_syslog(stripped)
    if syslog is not None:
        return syslog

    # 4. CSV – attempt only when there are multiple comma-separated tokens
    if "," in stripped:
        try:
            reader = csv.reader(io.StringIO(stripped))
            rows = list(reader)
            if rows and len(rows[0]) > 1:
                # If exactly one row treat field indices as keys
                fields = rows[0]
                return {
                    "format": "csv",
                    "fields": fields,
                    "data": {str(i): v for i, v in enumerate(fields)},
                }
        except Exception:
            pass

    # 5. Fallback
    return {"format": "unknown", "raw": stripped}
