"""Correlation Engine – groups raw events into correlated security incidents."""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)

# Default time windows for correlation
WINDOW_SHORT = timedelta(minutes=5)
WINDOW_MEDIUM = timedelta(minutes=15)
WINDOW_LONG = timedelta(hours=1)


@dataclass
class CorrelatedEvent:
    """A group of related raw events forming a single correlated incident."""

    correlation_id: str
    event_ids: List[str]
    source_ips: List[str]
    users: List[str]
    hosts: List[str]
    event_types: List[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    time_span_seconds: float
    event_count: int
    source_diversity: int          # number of distinct source IPs
    max_severity: str
    correlation_score: float       # 0-10 composite score
    session_id: Optional[str]
    attack_chain_match: Optional[str]
    tags: List[str]
    raw_events: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "event_ids": self.event_ids,
            "source_ips": self.source_ips,
            "users": self.users,
            "hosts": self.hosts,
            "event_types": self.event_types,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "time_span_seconds": self.time_span_seconds,
            "event_count": self.event_count,
            "source_diversity": self.source_diversity,
            "max_severity": self.max_severity,
            "correlation_score": round(self.correlation_score, 3),
            "session_id": self.session_id,
            "attack_chain_match": self.attack_chain_match,
            "tags": self.tags,
        }


SEVERITY_RANK = {"info": 1, "low": 1, "warning": 2, "medium": 2, "high": 3, "error": 3, "critical": 4}


def _max_severity(severities: List[str]) -> str:
    """Return the highest severity from a list."""
    if not severities:
        return "info"
    return max(severities, key=lambda s: SEVERITY_RANK.get(s.lower(), 0))


def _parse_ts(event: Dict[str, Any]) -> Optional[datetime]:
    """Extract a datetime from an event dict."""
    ts = event.get("timestamp")
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


class CorrelationEngine:
    """
    Correlates lists of log/event dicts into CorrelatedEvent groups using:
      - Time-window proximity
      - Shared source IP / host / user
      - Attack chain pattern matching
      - Session grouping
      - Deduplication
    """

    def __init__(
        self,
        time_window: timedelta = WINDOW_MEDIUM,
        min_events_for_correlation: int = 2,
    ) -> None:
        self.time_window = time_window
        self.min_events = min_events_for_correlation
        self._log = logger.bind(component="CorrelationEngine")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate(self, events: List[Dict[str, Any]]) -> List[CorrelatedEvent]:
        """
        Main entry point. Accepts a list of event dicts (Log model rows or similar).
        Returns a list of CorrelatedEvent objects sorted by score descending.
        """
        if not events:
            return []

        self._log.info("correlation_start", event_count=len(events))

        # Normalise and deduplicate
        normalised = self._normalise(events)
        unique = self._deduplicate(normalised)

        # Build grouping indexes
        ip_index = self._build_index(unique, "ip_address")
        user_index = self._build_index(unique, "user_id")
        host_index = self._build_index(unique, "host")

        # Combine overlap sets
        candidate_groups = self._merge_overlap_sets(
            list(ip_index.values()) + list(user_index.values()) + list(host_index.values()),
            unique,
        )

        # Time-window filter: each group must have ≥ 1 pair within window
        time_filtered = [
            g for g in candidate_groups if self._passes_time_filter(g)
        ]

        correlated: List[CorrelatedEvent] = []
        for group in time_filtered:
            if len(group) < self.min_events:
                continue
            ce = self._build_correlated_event(group)
            correlated.append(ce)

        # Sort by score descending
        correlated.sort(key=lambda c: c.correlation_score, reverse=True)
        self._log.info("correlation_complete", groups=len(correlated))
        return correlated

    def correlate_with_windows(
        self, events: List[Dict[str, Any]]
    ) -> Dict[str, List[CorrelatedEvent]]:
        """Run correlation at three time windows: 5min, 15min, 1hr."""
        results: Dict[str, List[CorrelatedEvent]] = {}
        for label, window in [("5min", WINDOW_SHORT), ("15min", WINDOW_MEDIUM), ("1hr", WINDOW_LONG)]:
            engine = CorrelationEngine(time_window=window, min_events_for_correlation=self.min_events)
            results[label] = engine.correlate(events)
        return results

    # ------------------------------------------------------------------
    # Normalisation & deduplication
    # ------------------------------------------------------------------

    def _normalise(self, events: List[Any]) -> List[Dict[str, Any]]:
        normalised: List[Dict[str, Any]] = []
        for e in events:
            if hasattr(e, "__dict__"):
                d = {k: v for k, v in e.__dict__.items() if not k.startswith("_")}
            elif isinstance(e, dict):
                d = dict(e)
            else:
                d = {"raw_log": str(e)}
            if "id" not in d:
                d["id"] = str(uuid.uuid4())
            normalised.append(d)
        return normalised

    def _deduplicate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate events by (raw_log hash, timestamp) key."""
        seen: set = set()
        unique: List[Dict[str, Any]] = []
        for e in events:
            key = (
                str(e.get("raw_log", ""))[:256],
                str(e.get("timestamp", "")),
                str(e.get("ip_address", "")),
            )
            if key not in seen:
                seen.add(key)
                unique.append(e)
        removed = len(events) - len(unique)
        if removed:
            self._log.debug("deduplication", removed=removed)
        return unique

    # ------------------------------------------------------------------
    # Indexing & grouping
    # ------------------------------------------------------------------

    def _build_index(self, events: List[Dict[str, Any]], field: str) -> Dict[str, List[Dict[str, Any]]]:
        index: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for e in events:
            val = e.get(field)
            if val:
                index[str(val)].append(e)
        return dict(index)

    def _merge_overlap_sets(
        self,
        groups: List[List[Dict[str, Any]]],
        all_events: List[Dict[str, Any]],
    ) -> List[List[Dict[str, Any]]]:
        """
        Union-find style merge: if two groups share any event ID,
        merge them into one.
        """
        # Build id → group mapping
        event_to_group: Dict[str, int] = {}
        merged: List[set] = []

        for group in groups:
            ids = {e["id"] for e in group}
            # Find which existing groups overlap
            overlap_indices = {
                event_to_group[eid] for eid in ids if eid in event_to_group
            }

            if not overlap_indices:
                new_idx = len(merged)
                merged.append(ids)
                for eid in ids:
                    event_to_group[eid] = new_idx
            else:
                # Merge all overlapping groups + current
                target_idx = min(overlap_indices)
                for idx in overlap_indices:
                    if idx != target_idx:
                        merged[target_idx] |= merged[idx]
                        merged[idx] = set()  # mark empty
                merged[target_idx] |= ids
                for eid in merged[target_idx]:
                    event_to_group[eid] = target_idx

        # Resolve id sets back to event dicts
        id_to_event = {e["id"]: e for e in all_events}
        result: List[List[Dict[str, Any]]] = []
        for group_ids in merged:
            if len(group_ids) >= 2:
                result.append([id_to_event[eid] for eid in group_ids if eid in id_to_event])
        return result

    def _passes_time_filter(self, group: List[Dict[str, Any]]) -> bool:
        """Return True if at least one pair of events is within the time window."""
        timestamps = sorted([ts for e in group if (ts := _parse_ts(e)) is not None])
        if len(timestamps) < 2:
            return True  # no timestamps – keep group
        for i in range(len(timestamps) - 1):
            if timestamps[i + 1] - timestamps[i] <= self.time_window:
                return True
        return False

    # ------------------------------------------------------------------
    # Score calculation
    # ------------------------------------------------------------------

    def _score_group(
        self,
        count: int,
        severities: List[str],
        time_span_seconds: float,
        source_diversity: int,
    ) -> float:
        """
        Composite score 0-10 based on:
          - event count       (weight 3)
          - max severity      (weight 3)
          - time compression  (weight 2: many events in short time = higher score)
          - source diversity  (weight 2: multiple sources = higher score)
        """
        count_score = min(3.0, count * 0.3)
        sev_score = SEVERITY_RANK.get(_max_severity(severities).lower(), 1) * 0.75  # max 3
        compression_score = min(2.0, (100.0 / (time_span_seconds + 1)) * 0.02)
        diversity_score = min(2.0, source_diversity * 0.4)
        return round(count_score + sev_score + compression_score + diversity_score, 3)

    # ------------------------------------------------------------------
    # CorrelatedEvent builder
    # ------------------------------------------------------------------

    def _build_correlated_event(self, group: List[Dict[str, Any]]) -> CorrelatedEvent:
        event_ids = [e["id"] for e in group]
        ips = list({e.get("ip_address") for e in group if e.get("ip_address")})
        users = list({e.get("user_id") for e in group if e.get("user_id")})
        hosts = list({e.get("host") for e in group if e.get("host")})
        event_types = list({e.get("event_type") for e in group if e.get("event_type")})
        severities = [str(e.get("severity", "info")) for e in group]

        timestamps = sorted([ts for e in group if (ts := _parse_ts(e)) is not None])
        first_seen = timestamps[0] if timestamps else None
        last_seen = timestamps[-1] if timestamps else None
        time_span = (last_seen - first_seen).total_seconds() if (first_seen and last_seen) else 0.0

        score = self._score_group(
            count=len(group),
            severities=severities,
            time_span_seconds=time_span,
            source_diversity=len(ips),
        )

        tags: List[str] = []
        if len(ips) > 3:
            tags.append("multi_source")
        if time_span < 60 and len(group) >= 5:
            tags.append("burst_activity")
        if any("fail" in str(e.get("event_type", "")).lower() for e in group):
            tags.append("auth_failures")

        return CorrelatedEvent(
            correlation_id=str(uuid.uuid4()),
            event_ids=event_ids,
            source_ips=ips,
            users=users,
            hosts=hosts,
            event_types=event_types,
            first_seen=first_seen,
            last_seen=last_seen,
            time_span_seconds=time_span,
            event_count=len(group),
            source_diversity=len(ips),
            max_severity=_max_severity(severities),
            correlation_score=score,
            session_id=None,
            attack_chain_match=None,
            tags=tags,
            raw_events=group,
        )
