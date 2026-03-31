"""Session Tracker – groups events into user/source sessions and detects anomalies."""

from __future__ import annotations

import math
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)

SESSION_TIMEOUT = timedelta(minutes=30)
IMPOSSIBLE_TRAVEL_SPEED_KMH = 900  # faster than this = impossible travel

# Well-known GeoIP approximations for RFC-1918 ranges (internal = same location)
PRIVATE_RANGES = [
    ("10.", 0), ("192.168.", 0), ("172.16.", 0), ("172.17.", 0),
    ("172.18.", 0), ("172.19.", 0), ("172.20.", 0), ("172.21.", 0),
    ("172.22.", 0), ("172.23.", 0), ("172.24.", 0), ("172.25.", 0),
    ("172.26.", 0), ("172.27.", 0), ("172.28.", 0), ("172.29.", 0),
    ("172.30.", 0), ("172.31.", 0),
]


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix, _ in PRIVATE_RANGES)


@dataclass
class Session:
    """Represents a contiguous period of activity by a source IP and/or user."""

    session_id: str
    source_ip: Optional[str]
    user: Optional[str]
    host: Optional[str]
    start_time: datetime
    end_time: datetime
    events: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    anomalies: List[str] = field(default_factory=list)
    closed: bool = False

    # Geographic tracking
    geo_locations: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()

    @property
    def event_count(self) -> int:
        return len(self.events)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "user": self.user,
            "host": self.host,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": self.duration_seconds,
            "event_count": self.event_count,
            "risk_score": round(self.risk_score, 3),
            "anomalies": self.anomalies,
            "closed": self.closed,
        }


class SessionTracker:
    """
    Tracks and manages user/source sessions across the event stream.

    Detects:
      - Impossible travel (same user, different locations in short time)
      - Privilege escalation within a session
      - Abnormally long sessions
      - Abnormal event density (burst)
    """

    def __init__(self, session_timeout: timedelta = SESSION_TIMEOUT) -> None:
        self.session_timeout = session_timeout
        self._active: Dict[str, Session] = {}   # key → Session
        self._closed: List[Session] = []
        self._log = logger.bind(component="SessionTracker")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_event(self, event: Dict[str, Any]) -> Session:
        """
        Add an event to the appropriate session (or create a new one).
        Returns the session the event was added to.
        """
        key = self._session_key(event)
        ts = self._parse_ts(event)
        if ts is None:
            ts = datetime.now(timezone.utc)

        if key in self._active:
            session = self._active[key]
            if ts - session.end_time > self.session_timeout:
                # Timeout – close old session, start fresh
                self._close_session(session)
                session = self._new_session(key, event, ts)
            else:
                session.end_time = ts
                session.events.append(event)
        else:
            session = self._new_session(key, event, ts)

        self._active[key] = session
        self._detect_anomalies(session, event)
        return session

    def process_events(self, events: List[Dict[str, Any]]) -> List[Session]:
        """Process a batch of events. Returns all sessions (active + just closed)."""
        # Sort by timestamp first
        sorted_events = sorted(events, key=lambda e: self._parse_ts(e) or datetime.min.replace(tzinfo=timezone.utc))
        for event in sorted_events:
            self.process_event(event)
        return self.get_all_sessions()

    def close_expired(self, reference_time: Optional[datetime] = None) -> List[Session]:
        """Close all sessions that have exceeded the timeout."""
        now = reference_time or datetime.now(timezone.utc)
        expired_keys = [
            k for k, s in self._active.items()
            if now - s.end_time > self.session_timeout
        ]
        closed: List[Session] = []
        for k in expired_keys:
            s = self._active.pop(k)
            self._close_session(s)
            closed.append(s)
        return closed

    def get_active_sessions(self) -> List[Session]:
        return list(self._active.values())

    def get_closed_sessions(self) -> List[Session]:
        return list(self._closed)

    def get_all_sessions(self) -> List[Session]:
        return list(self._active.values()) + self._closed

    def get_high_risk_sessions(self, threshold: float = 6.0) -> List[Session]:
        return [s for s in self.get_all_sessions() if s.risk_score >= threshold]

    def get_session_by_id(self, session_id: str) -> Optional[Session]:
        for s in self.get_all_sessions():
            if s.session_id == session_id:
                return s
        return None

    def reset(self) -> None:
        self._active.clear()
        self._closed.clear()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "active_sessions": [s.to_dict() for s in self._active.values()],
            "closed_sessions": [s.to_dict() for s in self._closed],
            "total_sessions": len(self._active) + len(self._closed),
            "high_risk_count": len(self.get_high_risk_sessions()),
        }

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def _detect_anomalies(self, session: Session, new_event: Dict[str, Any]) -> None:
        """Run all anomaly checks and update session.risk_score."""
        self._check_burst(session)
        self._check_privilege_escalation(session, new_event)
        self._check_abnormal_duration(session)
        self._check_impossible_travel(session, new_event)
        session.risk_score = self._compute_risk(session)

    def _check_burst(self, session: Session) -> None:
        """Flag if event rate exceeds threshold (events per minute)."""
        if session.duration_seconds < 1:
            return
        rate = session.event_count / (session.duration_seconds / 60.0)
        if rate > 60 and "burst_activity" not in session.anomalies:
            session.anomalies.append("burst_activity")
            self._log.warning("burst_activity", session_id=session.session_id, rate=round(rate, 1))

    def _check_privilege_escalation(self, session: Session, event: Dict[str, Any]) -> None:
        """Flag if a privileged action follows a non-privileged sequence."""
        raw = str(event.get("raw_log", "") or event.get("event_type", "")).lower()
        priv_keywords = {"sudo", "su ", "runas", "admin", "root", "privilege", "elevated", "setuid"}
        if any(kw in raw for kw in priv_keywords):
            if "privilege_escalation" not in session.anomalies:
                session.anomalies.append("privilege_escalation")

    def _check_abnormal_duration(self, session: Session) -> None:
        """Flag sessions lasting more than 8 hours."""
        if session.duration_seconds > 8 * 3600 and "abnormal_duration" not in session.anomalies:
            session.anomalies.append("abnormal_duration")

    def _check_impossible_travel(self, session: Session, event: Dict[str, Any]) -> None:
        """
        Check for impossible travel.
        Uses simple country-code comparison if available in parsed_fields,
        otherwise skips (no external GeoIP dep required).
        """
        parsed = event.get("parsed_fields") or {}
        country = parsed.get("geoip_country") or parsed.get("country_code")
        if not country:
            return

        if session.geo_locations:
            last = session.geo_locations[-1]
            last_country = last.get("country")
            last_ts = last.get("timestamp")
            if last_country and last_country != country and last_ts:
                elapsed_hours = (session.end_time - last_ts).total_seconds() / 3600.0
                if elapsed_hours < 2 and "impossible_travel" not in session.anomalies:
                    session.anomalies.append("impossible_travel")
                    self._log.warning(
                        "impossible_travel",
                        session_id=session.session_id,
                        from_country=last_country,
                        to_country=country,
                        elapsed_hours=round(elapsed_hours, 2),
                    )

        session.geo_locations.append({
            "country": country,
            "timestamp": session.end_time,
        })

    def _compute_risk(self, session: Session) -> float:
        """Compute a 0-10 risk score for the session."""
        score = 0.0
        anomaly_weights = {
            "burst_activity": 2.5,
            "privilege_escalation": 3.0,
            "abnormal_duration": 1.5,
            "impossible_travel": 4.0,
        }
        for anomaly in session.anomalies:
            score += anomaly_weights.get(anomaly, 1.0)

        # Event count contribution
        score += min(2.0, session.event_count * 0.02)
        return min(10.0, round(score, 2))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _session_key(self, event: Dict[str, Any]) -> str:
        """Create a session bucket key from IP + user + host."""
        ip = event.get("ip_address", "") or ""
        user = event.get("user_id", "") or ""
        host = event.get("host", "") or ""
        return f"{ip}|{user}|{host}" if (ip or user) else str(uuid.uuid4())

    def _new_session(self, key: str, event: Dict[str, Any], ts: datetime) -> Session:
        s = Session(
            session_id=str(uuid.uuid4()),
            source_ip=event.get("ip_address"),
            user=event.get("user_id"),
            host=event.get("host"),
            start_time=ts,
            end_time=ts,
            events=[event],
        )
        self._log.debug("session_created", session_id=s.session_id, key=key)
        return s

    def _close_session(self, session: Session) -> None:
        session.closed = True
        self._closed.append(session)
        self._log.debug(
            "session_closed",
            session_id=session.session_id,
            duration_s=round(session.duration_seconds),
            events=session.event_count,
            risk=session.risk_score,
        )

    def _parse_ts(self, event: Dict[str, Any]) -> Optional[datetime]:
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
