import uuid
import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, DateTime, Boolean, Text, Float,
    Index, Enum as SAEnum, Integer,
)
from sqlalchemy.types import JSON

from .database import Base


class SourceType(str, enum.Enum):
    system = "system"
    network = "network"
    application = "application"
    custom = "custom"


class LogSeverity(str, enum.Enum):
    info = "info"
    warning = "warning"
    error = "error"
    critical = "critical"


class Log(Base):
    __tablename__ = "logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    source = Column(String(255), nullable=False, index=True)
    source_type = Column(SAEnum(SourceType), nullable=False, default=SourceType.system)
    raw_log = Column(Text, nullable=False)
    normalized_log = Column(JSON, nullable=True)
    severity = Column(SAEnum(LogSeverity), nullable=False, default=LogSeverity.info, index=True)
    tags = Column(JSON, nullable=True, default=list)
    host = Column(String(255), nullable=True, index=True)
    ip_address = Column(String(45), nullable=True, index=True)
    user_id = Column(String(255), nullable=True, index=True)
    process_name = Column(String(255), nullable=True)
    event_type = Column(String(100), nullable=True, index=True)
    parsed_fields = Column(JSON, nullable=True)
    is_processed = Column(Boolean, default=False, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_logs_timestamp_severity", "timestamp", "severity"),
        Index("ix_logs_source_timestamp", "source", "timestamp"),
        Index("ix_logs_host_timestamp", "host", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<Log id={self.id} source={self.source} severity={self.severity}>"
