from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class IncidentStatus(str, Enum):
    open = "open"
    triaging = "triaging"
    acknowledged = "acknowledged"
    resolved = "resolved"
    suppressed = "suppressed"


class AlertPayload(BaseModel):
    source: str = Field(..., max_length=120)
    rule_id: str = Field(..., max_length=120)
    description: str = Field(..., max_length=2000)
    labels: dict[str, str] = Field(default_factory=dict)
    fingerprint: str = Field(..., max_length=256)
    raw_payload: Optional[dict] = None


class TriageUpdate(BaseModel):
    severity: Optional[Severity] = None
    status: Optional[IncidentStatus] = None
    assignee: Optional[str] = Field(None, max_length=120)
    notes: Optional[str] = Field(None, max_length=5000)


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    fingerprint: str
    source: str
    rule_id: str
    description: str
    labels: dict[str, str]
    severity: Severity
    status: IncidentStatus = IncidentStatus.open
    assignee: Optional[str] = None
    notes: Optional[str] = None
    alert_count: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_payload: Optional[dict] = None

    class Config:
        use_enum_values = True


class IncidentBrief(BaseModel):
    id: str
    fingerprint: str
    severity: Severity
    status: IncidentStatus
    alert_count: int
    created_at: datetime

    class Config:
        use_enum_values = True