import uuid
import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, DateTime, Boolean, Integer, Text,
    Index, Enum as SAEnum,
)
from sqlalchemy.types import JSON

from .database import Base


class RuleType(str, enum.Enum):
    signature = "signature"
    pattern = "pattern"
    threshold = "threshold"
    statistical = "statistical"


class Rule(Base):
    __tablename__ = "rules"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    rule_type = Column(SAEnum(RuleType), nullable=False, default=RuleType.signature)
    condition = Column(JSON, nullable=False)
    severity = Column(String(50), nullable=False, default="medium")
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    priority = Column(Integer, default=50, nullable=False)
    tags = Column(JSON, nullable=True, default=list)
    created_by = Column(String(255), nullable=True)
    hit_count = Column(Integer, default=0, nullable=False)
    last_triggered = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_rules_enabled_priority", "enabled", "priority"),
        Index("ix_rules_type_enabled", "rule_type", "enabled"),
    )

    def __repr__(self) -> str:
        return f"<Rule id={self.id} name={self.name!r} type={self.rule_type}>"
