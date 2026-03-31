import uuid
import enum
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Text, Index, Enum as SAEnum
from sqlalchemy.types import JSON

from .database import Base


class IncidentStatus(str, enum.Enum):
    open = "open"
    in_progress = "in_progress"
    contained = "contained"
    eradicated = "eradicated"
    recovered = "recovered"
    closed = "closed"


class IncidentSeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(SAEnum(IncidentStatus), nullable=False, default=IncidentStatus.open, index=True)
    severity = Column(SAEnum(IncidentSeverity), nullable=False, default=IncidentSeverity.medium, index=True)
    alert_ids = Column(JSON, nullable=True, default=list)
    affected_hosts = Column(JSON, nullable=True, default=list)
    timeline = Column(JSON, nullable=True, default=list)
    playbook_id = Column(String(36), nullable=True)
    assigned_to = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    closed_at = Column(DateTime(timezone=True), nullable=True)
    root_cause = Column(Text, nullable=True)
    lessons_learned = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_incidents_status_severity", "status", "severity"),
        Index("ix_incidents_created_status", "created_at", "status"),
    )

    def __repr__(self) -> str:
        return f"<Incident id={self.id} title={self.title!r} status={self.status}>"
