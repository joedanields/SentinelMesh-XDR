import uuid
import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, DateTime, Float, Text,
    Index, ForeignKey, Enum as SAEnum,
)
from sqlalchemy.types import JSON

from .database import Base


class AlertSeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(str, enum.Enum):
    new = "new"
    investigating = "investigating"
    resolved = "resolved"
    false_positive = "false_positive"


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(SAEnum(AlertSeverity), nullable=False, default=AlertSeverity.medium, index=True)
    status = Column(SAEnum(AlertStatus), nullable=False, default=AlertStatus.new, index=True)
    rule_id = Column(
        String(36),
        ForeignKey("rules.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    log_ids = Column(JSON, nullable=True, default=list)
    risk_score = Column(Float, nullable=True)
    confidence = Column(Float, nullable=True)
    mitre_technique = Column(String(100), nullable=True)
    tags = Column(JSON, nullable=True, default=list)
    assigned_to = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_alerts_severity_status", "severity", "status"),
        Index("ix_alerts_created_severity", "created_at", "severity"),
    )

    def __repr__(self) -> str:
        return f"<Alert id={self.id} title={self.title!r} severity={self.severity}>"
