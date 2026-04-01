from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Generic, List, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from models.log_models import LogSeverity, SourceType
from models.alert_models import AlertSeverity, AlertStatus
from models.incident_models import IncidentSeverity, IncidentStatus
from models.rule_models import RuleType
from models.user_models import UserRole

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    size: int
    pages: int
    has_next: bool
    has_prev: bool


# ---------------------------------------------------------------------------
# Log schemas
# ---------------------------------------------------------------------------


class LogCreate(BaseModel):
    timestamp: datetime
    source: str = Field(..., max_length=255)
    source_type: SourceType = SourceType.system
    raw_log: str
    severity: LogSeverity = LogSeverity.info
    tags: List[str] = Field(default_factory=list)
    host: Optional[str] = Field(default=None, max_length=255)
    ip_address: Optional[str] = Field(default=None, max_length=45)
    user_id: Optional[str] = Field(default=None, max_length=255)
    process_name: Optional[str] = Field(default=None, max_length=255)
    event_type: Optional[str] = Field(default=None, max_length=100)
    parsed_fields: Optional[Dict[str, Any]] = None


class LogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    source: str
    source_type: SourceType
    raw_log: str
    normalized_log: Optional[Dict[str, Any]] = None
    severity: LogSeverity
    tags: Optional[List[str]] = None
    host: Optional[str] = None
    ip_address: Optional[str] = None
    user_id: Optional[str] = None
    process_name: Optional[str] = None
    event_type: Optional[str] = None
    parsed_fields: Optional[Dict[str, Any]] = None
    is_processed: bool
    created_at: datetime
    updated_at: datetime


class LogFilter(BaseModel):
    severity: Optional[LogSeverity] = None
    source_type: Optional[SourceType] = None
    host: Optional[str] = None
    ip_address: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    is_processed: Optional[bool] = None
    tags: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# Alert schemas
# ---------------------------------------------------------------------------


class AlertCreate(BaseModel):
    title: str = Field(..., max_length=500)
    description: Optional[str] = None
    severity: AlertSeverity = AlertSeverity.medium
    rule_id: Optional[str] = Field(default=None, max_length=36)
    log_ids: List[str] = Field(default_factory=list)
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    mitre_technique: Optional[str] = Field(default=None, max_length=100)
    tags: List[str] = Field(default_factory=list)


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: Optional[str] = None
    severity: AlertSeverity
    status: AlertStatus
    rule_id: Optional[str] = None
    log_ids: Optional[List[str]] = None
    risk_score: Optional[float] = None
    confidence: Optional[float] = None
    mitre_technique: Optional[str] = None
    tags: Optional[List[str]] = None
    assigned_to: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None


class AlertUpdate(BaseModel):
    title: Optional[str] = Field(default=None, max_length=500)
    description: Optional[str] = None
    severity: Optional[AlertSeverity] = None
    status: Optional[AlertStatus] = None
    assigned_to: Optional[str] = Field(default=None, max_length=255)
    tags: Optional[List[str]] = None


class AlertFilter(BaseModel):
    severity: Optional[AlertSeverity] = None
    status: Optional[AlertStatus] = None
    assigned_to: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    mitre_technique: Optional[str] = None


# ---------------------------------------------------------------------------
# Incident schemas
# ---------------------------------------------------------------------------


class IncidentCreate(BaseModel):
    title: str = Field(..., max_length=500)
    description: Optional[str] = None
    severity: IncidentSeverity = IncidentSeverity.medium
    alert_ids: List[str] = Field(default_factory=list)
    affected_hosts: List[str] = Field(default_factory=list)
    playbook_id: Optional[str] = Field(default=None, max_length=36)
    assigned_to: Optional[str] = Field(default=None, max_length=255)


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: Optional[str] = None
    status: IncidentStatus
    severity: IncidentSeverity
    alert_ids: Optional[List[str]] = None
    affected_hosts: Optional[List[str]] = None
    timeline: Optional[List[Dict[str, Any]]] = None
    playbook_id: Optional[str] = None
    assigned_to: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    root_cause: Optional[str] = None
    lessons_learned: Optional[str] = None


class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(default=None, max_length=500)
    description: Optional[str] = None
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    alert_ids: Optional[List[str]] = None
    affected_hosts: Optional[List[str]] = None
    assigned_to: Optional[str] = Field(default=None, max_length=255)
    root_cause: Optional[str] = None
    lessons_learned: Optional[str] = None


# ---------------------------------------------------------------------------
# Rule schemas
# ---------------------------------------------------------------------------


class RuleCreate(BaseModel):
    name: str = Field(..., max_length=255)
    description: Optional[str] = None
    rule_type: RuleType = RuleType.signature
    condition: Dict[str, Any]
    severity: str = Field(default="medium", max_length=50)
    priority: int = Field(default=50, ge=1, le=100)
    tags: List[str] = Field(default_factory=list)
    created_by: Optional[str] = Field(default=None, max_length=255)

    @field_validator("condition")
    @classmethod
    def condition_must_not_be_empty(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if not v:
            raise ValueError("condition must not be empty")
        return v


class RuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None
    rule_type: RuleType
    condition: Dict[str, Any]
    severity: str
    enabled: bool
    priority: int
    tags: Optional[List[str]] = None
    created_by: Optional[str] = None
    hit_count: int
    last_triggered: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class RuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=255)
    description: Optional[str] = None
    condition: Optional[Dict[str, Any]] = None
    severity: Optional[str] = Field(default=None, max_length=50)
    enabled: Optional[bool] = None
    priority: Optional[int] = Field(default=None, ge=1, le=100)
    tags: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# User schemas
# ---------------------------------------------------------------------------


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    email: str = Field(..., max_length=255)
    password: str

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters long")
        return v


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class UserLogin(BaseModel):
    username: str
    password: str


# ---------------------------------------------------------------------------
# Auth / token schemas
# ---------------------------------------------------------------------------


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[UserRole] = None


# ---------------------------------------------------------------------------
# Health-check schema
# ---------------------------------------------------------------------------


class HealthCheck(BaseModel):
    status: str
    version: str
    environment: str
    database: str
    redis: str
    uptime_seconds: float
