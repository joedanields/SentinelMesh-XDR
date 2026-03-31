"""Input validators for SentinelMesh XDR."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta
from typing import Any

# ---------------------------------------------------------------------------
# IP / network validation
# ---------------------------------------------------------------------------


def validate_ip_address(ip: str) -> bool:
    """Return ``True`` if *ip* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """Return ``True`` if *cidr* is a valid IPv4 or IPv6 network in CIDR notation."""
    try:
        ipaddress.ip_network(cidr.strip(), strict=False)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Log format validation
# ---------------------------------------------------------------------------


def validate_log_format(log_data: dict, required_fields: list[str]) -> tuple[bool, list[str]]:
    """Check that all *required_fields* are present (and non-None) in *log_data*.

    Returns ``(True, [])`` on success, or ``(False, [missing_field, …])`` on failure.
    """
    missing = [f for f in required_fields if f not in log_data or log_data[f] is None]
    return (len(missing) == 0, missing)


# ---------------------------------------------------------------------------
# Rule condition validation
# ---------------------------------------------------------------------------

_THRESHOLD_OPERATORS = frozenset({">", "<", ">=", "<=", "=="})
_STATISTICAL_METHODS = frozenset({"zscore", "iqr", "mad"})


def validate_rule_condition(condition: dict) -> tuple[bool, str]:
    """Validate a detection rule condition dictionary.

    Required key: ``"type"`` (str).

    Type-specific requirements
    --------------------------
    * ``signature``:  ``"pattern"`` (str)
    * ``threshold``:  ``"field"`` (str), ``"operator"`` (one of ``> < >= <= ==``),
                      ``"value"`` (numeric), ``"window_seconds"`` (int)
    * ``pattern``:    ``"regex"`` (str, must compile)
    * ``statistical``: ``"field"`` (str), ``"method"`` (zscore/iqr/mad),
                       ``"threshold"`` (float)
    """
    if not isinstance(condition, dict):
        return False, "condition must be a dict"

    rule_type = condition.get("type")
    if not rule_type:
        return False, "condition must have a 'type' field"

    if rule_type == "signature":
        pattern = condition.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            return False, "signature condition requires a non-empty 'pattern' string"

    elif rule_type == "threshold":
        for required_key in ("field", "operator", "value", "window_seconds"):
            if required_key not in condition:
                return False, f"threshold condition requires '{required_key}'"
        if condition["operator"] not in _THRESHOLD_OPERATORS:
            return False, f"operator must be one of {sorted(_THRESHOLD_OPERATORS)}"
        if not isinstance(condition["value"], (int, float)):
            return False, "'value' must be numeric"
        if not isinstance(condition["window_seconds"], int) or condition["window_seconds"] <= 0:
            return False, "'window_seconds' must be a positive integer"

    elif rule_type == "pattern":
        regex_str = condition.get("regex")
        if not isinstance(regex_str, str) or not regex_str:
            return False, "pattern condition requires a non-empty 'regex' string"
        try:
            re.compile(regex_str)
        except re.error as exc:
            return False, f"invalid regex: {exc}"

    elif rule_type == "statistical":
        for required_key in ("field", "method", "threshold"):
            if required_key not in condition:
                return False, f"statistical condition requires '{required_key}'"
        if condition["method"] not in _STATISTICAL_METHODS:
            return False, f"method must be one of {sorted(_STATISTICAL_METHODS)}"
        if not isinstance(condition["threshold"], (int, float)):
            return False, "'threshold' must be a float"

    else:
        return False, f"unknown condition type: {rule_type!r}"

    return True, ""


# ---------------------------------------------------------------------------
# Date range validation
# ---------------------------------------------------------------------------

_MAX_DATE_RANGE_DAYS = 365


def validate_date_range(start: datetime, end: datetime) -> tuple[bool, str]:
    """Validate that *end* is after *start* and the range ≤ 365 days."""
    if end <= start:
        return False, "end datetime must be after start datetime"
    if (end - start) > timedelta(days=_MAX_DATE_RANGE_DAYS):
        return False, f"date range cannot exceed {_MAX_DATE_RANGE_DAYS} days"
    return True, ""


# ---------------------------------------------------------------------------
# Severity validation
# ---------------------------------------------------------------------------

_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "warning", "error"})


def validate_severity(severity: str) -> bool:
    """Return ``True`` if *severity* is one of the accepted severity levels."""
    return severity.lower() in _VALID_SEVERITIES


# ---------------------------------------------------------------------------
# Email validation
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)


def validate_email(email: str) -> bool:
    """Return ``True`` if *email* matches a basic RFC-5322-inspired pattern."""
    return bool(_EMAIL_RE.match(email.strip()))


# ---------------------------------------------------------------------------
# Pagination validation
# ---------------------------------------------------------------------------

_MAX_PAGE_SIZE = 1000


def validate_pagination_params(page: int, size: int) -> tuple[bool, str]:
    """Validate pagination parameters.

    * ``page`` must be ≥ 1.
    * ``size`` must be between 1 and 1 000 (inclusive).
    """
    if page < 1:
        return False, "page must be >= 1"
    if not (1 <= size <= _MAX_PAGE_SIZE):
        return False, f"size must be between 1 and {_MAX_PAGE_SIZE}"
    return True, ""
