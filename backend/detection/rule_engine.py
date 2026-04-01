"""Detection rule engine – evaluates log events against configurable rules."""
from __future__ import annotations

import re
import time
import uuid
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    rule_type: str
    severity: str
    matched_fields: dict[str, Any]
    confidence: float        # 0.0 – 1.0
    description: str = ""
    mitre_technique: str = ""
    matched_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "rule_type": self.rule_type,
            "severity": self.severity,
            "matched_fields": self.matched_fields,
            "confidence": self.confidence,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "matched_at": self.matched_at,
        }


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------


class _BaseRule:
    def __init__(self, rule_id: str, name: str, severity: str, priority: int,
                 description: str = "", mitre_technique: str = "", enabled: bool = True) -> None:
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.priority = priority
        self.description = description
        self.mitre_technique = mitre_technique
        self.enabled = enabled
        self.hit_count = 0
        self.total_eval_time_ms: float = 0.0
        self.last_triggered: str | None = None

    def evaluate(self, log: dict[str, Any]) -> RuleMatch | None:
        raise NotImplementedError

    def _record_hit(self) -> None:
        self.hit_count += 1
        self.last_triggered = datetime.now(timezone.utc).isoformat()

    def perf_stats(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "hit_count": self.hit_count,
            "avg_eval_ms": round(self.total_eval_time_ms / max(1, self.hit_count), 4),
            "last_triggered": self.last_triggered,
        }


class SignatureRule(_BaseRule):
    """Match exact field values.

    ``condition`` format::

        {
            "field": "event_type",
            "value": "ssh_login_failure",          # exact match
            "fields": {"severity": "warning"},     # optional additional fields
        }
    """

    def __init__(self, rule_id: str, name: str, severity: str, priority: int,
                 condition: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(rule_id, name, severity, priority, **kwargs)
        self.condition = condition

    def evaluate(self, log: dict[str, Any]) -> RuleMatch | None:
        t0 = time.perf_counter()
        try:
            # Primary field match
            field = self.condition.get("field", "")
            expected = self.condition.get("value", "")
            if field and str(log.get(field, "")).lower() != str(expected).lower():
                return None

            # Additional field constraints
            for f, v in self.condition.get("fields", {}).items():
                if str(log.get(f, "")).lower() != str(v).lower():
                    return None

            self._record_hit()
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                rule_type="signature",
                severity=self.severity,
                matched_fields={field: log.get(field), **self.condition.get("fields", {})},
                confidence=0.9,
                description=self.description,
                mitre_technique=self.mitre_technique,
            )
        finally:
            self.total_eval_time_ms += (time.perf_counter() - t0) * 1000


class PatternRule(_BaseRule):
    """Match a compiled regex against any (or a specific) log field.

    ``condition`` format::

        {
            "field": "message",               # omit to search all string fields
            "pattern": "(?i)failed password",
            "flags": 0                        # optional re flags
        }
    """

    def __init__(self, rule_id: str, name: str, severity: str, priority: int,
                 condition: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(rule_id, name, severity, priority, **kwargs)
        self.condition = condition
        flags = condition.get("flags", re.IGNORECASE)
        self._regex = re.compile(condition["pattern"], flags)
        self._target_field: str = condition.get("field", "")

    def evaluate(self, log: dict[str, Any]) -> RuleMatch | None:
        t0 = time.perf_counter()
        try:
            if self._target_field:
                text = str(log.get(self._target_field, ""))
                m = self._regex.search(text)
                if not m:
                    return None
                matched = {self._target_field: text[:200]}
            else:
                # Search all string fields
                matched = {}
                for k, v in log.items():
                    if isinstance(v, str) and self._regex.search(v):
                        matched[k] = v[:200]
                if not matched:
                    return None

            self._record_hit()
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                rule_type="pattern",
                severity=self.severity,
                matched_fields=matched,
                confidence=0.85,
                description=self.description,
                mitre_technique=self.mitre_technique,
            )
        finally:
            self.total_eval_time_ms += (time.perf_counter() - t0) * 1000


class ThresholdRule(_BaseRule):
    """Trigger when a field value appears more than *threshold* times within *window_seconds*.

    ``condition`` format::

        {
            "field": "ip_address",
            "threshold": 5,
            "window_seconds": 60,
            "filter": {"event_type": "ssh_login_failure"}   # optional pre-filter
        }
    """

    def __init__(self, rule_id: str, name: str, severity: str, priority: int,
                 condition: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(rule_id, name, severity, priority, **kwargs)
        self.condition = condition
        self.field = condition["field"]
        self.threshold = int(condition["threshold"])
        self.window_seconds = float(condition.get("window_seconds", 60))
        self.filter_fields: dict[str, str] = condition.get("filter", {})
        # Sliding window: key -> deque of timestamps
        self._windows: dict[str, list[float]] = defaultdict(list)

    def evaluate(self, log: dict[str, Any]) -> RuleMatch | None:
        t0 = time.perf_counter()
        try:
            # Apply pre-filter
            for f, v in self.filter_fields.items():
                if str(log.get(f, "")).lower() != str(v).lower():
                    return None

            key = str(log.get(self.field, ""))
            if not key:
                return None

            now = time.monotonic()
            window = self._windows[key]
            cutoff = now - self.window_seconds
            # Purge expired timestamps
            while window and window[0] < cutoff:
                window.pop(0)
            window.append(now)

            if len(window) >= self.threshold:
                self._record_hit()
                return RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    rule_type="threshold",
                    severity=self.severity,
                    matched_fields={
                        self.field: key,
                        "count": len(window),
                        "window_seconds": self.window_seconds,
                        "threshold": self.threshold,
                    },
                    confidence=min(1.0, len(window) / (self.threshold * 2)),
                    description=self.description,
                    mitre_technique=self.mitre_technique,
                )
            return None
        finally:
            self.total_eval_time_ms += (time.perf_counter() - t0) * 1000


class StatisticalRule(_BaseRule):
    """Flag a numeric field value as anomalous if it deviates more than
    *z_threshold* standard deviations from the rolling mean.

    ``condition`` format::

        {
            "field": "parsed_fields.bytes",
            "z_threshold": 3.0,
            "min_samples": 30
        }
    """

    def __init__(self, rule_id: str, name: str, severity: str, priority: int,
                 condition: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(rule_id, name, severity, priority, **kwargs)
        self.condition = condition
        self.field = condition["field"]
        self.z_threshold = float(condition.get("z_threshold", 3.0))
        self.min_samples = int(condition.get("min_samples", 30))
        # Use deque for O(1) removal from the left end
        from collections import deque as _deque
        self._samples: _deque[float] = _deque(maxlen=1000)

    def _get_field_value(self, log: dict[str, Any]) -> float | None:
        parts = self.field.split(".")
        val = log
        for p in parts:
            if not isinstance(val, dict):
                return None
            val = val.get(p)
        try:
            return float(val)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None

    def evaluate(self, log: dict[str, Any]) -> RuleMatch | None:
        t0 = time.perf_counter()
        try:
            value = self._get_field_value(log)
            if value is None:
                return None

            self._samples.append(value)
            # deque with maxlen=1000 handles eviction automatically

            if len(self._samples) < self.min_samples:
                return None

            mean = sum(self._samples) / len(self._samples)
            variance = sum((x - mean) ** 2 for x in self._samples) / len(self._samples)
            std = variance ** 0.5
            if std == 0:
                return None

            z_score = abs(value - mean) / std
            if z_score < self.z_threshold:
                return None

            self._record_hit()
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                rule_type="statistical",
                severity=self.severity,
                matched_fields={
                    "field": self.field,
                    "value": value,
                    "mean": round(mean, 4),
                    "std_dev": round(std, 4),
                    "z_score": round(z_score, 4),
                },
                confidence=min(1.0, (z_score - self.z_threshold) / self.z_threshold + 0.6),
                description=self.description,
                mitre_technique=self.mitre_technique,
            )
        finally:
            self.total_eval_time_ms += (time.perf_counter() - t0) * 1000


# ---------------------------------------------------------------------------
# LRU cache helper
# ---------------------------------------------------------------------------


class _LRUCache:
    def __init__(self, maxsize: int = 512) -> None:
        self._cache: OrderedDict[str, Any] = OrderedDict()
        self.maxsize = maxsize

    def get(self, key: str) -> Any | None:
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def set(self, key: str, value: Any) -> None:
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = value
        if len(self._cache) > self.maxsize:
            self._cache.popitem(last=False)


# ---------------------------------------------------------------------------
# RuleEngine
# ---------------------------------------------------------------------------


# Built-in rules that ship with the engine
_BUILTIN_RULES: list[dict[str, Any]] = [
    {
        "id": "SIG-001", "name": "SSH Brute Force Detection", "type": "threshold",
        "severity": "high", "priority": 90, "mitre_technique": "T1110",
        "description": "More than 5 SSH login failures from the same IP within 60 seconds.",
        "condition": {"field": "ip_address", "threshold": 5, "window_seconds": 60,
                      "filter": {"event_type": "ssh_login_failure"}},
    },
    {
        "id": "SIG-002", "name": "Sensitive File Access", "type": "pattern",
        "severity": "high", "priority": 85, "mitre_technique": "T1083",
        "description": "Attempt to read /etc/passwd, /etc/shadow, or similar.",
        "condition": {"pattern": r"/etc/(passwd|shadow|sudoers|crontab)", "field": "message"},
    },
    {
        "id": "SIG-003", "name": "Reverse Shell Attempt", "type": "pattern",
        "severity": "critical", "priority": 95, "mitre_technique": "T1059",
        "description": "Suspicious reverse-shell command pattern detected.",
        "condition": {"pattern": r"(bash\s+-i|/dev/tcp/|nc\s+-e|ncat\s+.*-e|python.*socket.*connect)", "field": "message"},
    },
    {
        "id": "SIG-004", "name": "Windows Privilege Escalation", "type": "signature",
        "severity": "high", "priority": 88, "mitre_technique": "T1078",
        "description": "Windows special privileges assigned to new logon (Event 4672).",
        "condition": {"field": "event_type", "value": "windows_event_4672"},
    },
    {
        "id": "SIG-005", "name": "HTTP Path Traversal", "type": "pattern",
        "severity": "high", "priority": 80, "mitre_technique": "T1190",
        "description": "Path traversal attempt in HTTP request.",
        "condition": {"pattern": r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e)", "field": "message"},
    },
    {
        "id": "SIG-006", "name": "Large Outbound Data Transfer", "type": "statistical",
        "severity": "medium", "priority": 60, "mitre_technique": "T1048",
        "description": "Unusually large response byte count – potential data exfiltration.",
        "condition": {"field": "parsed_fields.bytes", "z_threshold": 4.0, "min_samples": 50},
    },
    {
        "id": "SIG-007", "name": "New User Account Created (Windows)", "type": "signature",
        "severity": "medium", "priority": 70, "mitre_technique": "T1136",
        "description": "Windows account creation event detected.",
        "condition": {"field": "event_type", "value": "windows_event_4720"},
    },
    {
        "id": "SIG-008", "name": "Malicious DNS Query", "type": "pattern",
        "severity": "high", "priority": 82, "mitre_technique": "T1071.004",
        "description": "DNS query to known malicious or suspicious domain.",
        "condition": {"pattern": r"(evil|malware|c2|exfil|rat\.|botnet)", "field": "message"},
    },
    {
        "id": "SIG-009", "name": "Firewall Rule Violation", "type": "signature",
        "severity": "warning", "priority": 50, "mitre_technique": "T1562.004",
        "description": "Firewall DROP or REJECT action triggered.",
        "condition": {"field": "event_type", "value": "firewall_event",
                      "fields": {"severity": "warning"}},
    },
    {
        "id": "SIG-010", "name": "Rapid HTTP 4xx Errors", "type": "threshold",
        "severity": "medium", "priority": 65, "mitre_technique": "T1595",
        "description": "More than 20 HTTP 4xx responses from the same IP in 30 seconds – potential scan.",
        "condition": {"field": "ip_address", "threshold": 20, "window_seconds": 30},
    },
]


class RuleEngine:
    """Evaluate log events against a set of detection rules.

    Usage
    -----
    ::

        engine = RuleEngine()
        engine.load_builtin_rules()
        matches = engine.evaluate_log(log_dict)
    """

    def __init__(self, cache_size: int = 512) -> None:
        self._rules: dict[str, _BaseRule] = {}
        self._sorted_rules: list[_BaseRule] = []
        self._cache = _LRUCache(maxsize=cache_size)
        self._eval_count = 0
        self._match_count = 0
        self._log = logger.bind(component="RuleEngine")

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def load_builtin_rules(self) -> None:
        """Load the built-in rule set."""
        for r in _BUILTIN_RULES:
            self.add_rule_from_dict(r)
        self._log.info("built-in rules loaded", count=len(_BUILTIN_RULES))

    def add_rule_from_dict(self, d: dict[str, Any]) -> _BaseRule:
        rtype = d.get("type", "signature")
        kwargs: dict[str, Any] = {
            "description": d.get("description", ""),
            "mitre_technique": d.get("mitre_technique", ""),
            "enabled": d.get("enabled", True),
        }
        rule: _BaseRule
        if rtype == "signature":
            rule = SignatureRule(d["id"], d["name"], d["severity"], d.get("priority", 50), d["condition"], **kwargs)
        elif rtype == "pattern":
            rule = PatternRule(d["id"], d["name"], d["severity"], d.get("priority", 50), d["condition"], **kwargs)
        elif rtype == "threshold":
            rule = ThresholdRule(d["id"], d["name"], d["severity"], d.get("priority", 50), d["condition"], **kwargs)
        elif rtype == "statistical":
            rule = StatisticalRule(d["id"], d["name"], d["severity"], d.get("priority", 50), d["condition"], **kwargs)
        else:
            raise ValueError(f"Unknown rule type: {rtype!r}")

        self._rules[rule.rule_id] = rule
        self._rebuild_sorted()
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        if rule_id in self._rules:
            del self._rules[rule_id]
            self._rebuild_sorted()
            return True
        return False

    def enable_rule(self, rule_id: str) -> None:
        if rule_id in self._rules:
            self._rules[rule_id].enabled = True

    def disable_rule(self, rule_id: str) -> None:
        if rule_id in self._rules:
            self._rules[rule_id].enabled = False

    def _rebuild_sorted(self) -> None:
        self._sorted_rules = sorted(
            [r for r in self._rules.values() if r.enabled],
            key=lambda r: r.priority,
            reverse=True,
        )

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate_log(self, log: dict[str, Any]) -> list[RuleMatch]:
        """Evaluate *log* against all enabled rules in priority order."""
        self._eval_count += 1
        matches: list[RuleMatch] = []

        for rule in self._sorted_rules:
            try:
                match = rule.evaluate(log)
                if match:
                    matches.append(match)
                    self._match_count += 1
            except Exception as exc:
                self._log.warning("rule evaluation error", rule_id=rule.rule_id, error=str(exc))

        return matches

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def list_rules(self) -> list[dict[str, Any]]:
        rules = sorted(self._rules.values(), key=lambda r: r.priority, reverse=True)
        return [
            {
                "id": r.rule_id,
                "name": r.name,
                "type": r.__class__.__name__,
                "severity": r.severity,
                "priority": r.priority,
                "enabled": r.enabled,
                "hit_count": r.hit_count,
                "last_triggered": r.last_triggered,
            }
            for r in rules
        ]

    def performance_stats(self) -> dict[str, Any]:
        return {
            "total_evaluations": self._eval_count,
            "total_matches": self._match_count,
            "match_rate": round(self._match_count / max(1, self._eval_count), 4),
            "rules": [r.perf_stats() for r in self._sorted_rules],
        }
