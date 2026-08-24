from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# --- Auth ---
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class UserCreate(BaseModel):
    username: str
    password: str
    email: str = ""
    role: str = "analyst"


class UserOut(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# --- Events ---
class EventIn(BaseModel):
    timestamp: Optional[datetime] = None
    host: str = ""
    category: str = "other"
    action: str = ""
    outcome: str = "unknown"
    severity: str = "info"
    user: str = ""
    src_ip: str = ""
    src_port: Optional[int] = None
    dst_ip: str = ""
    dst_port: Optional[int] = None
    protocol: str = ""
    message: str = ""
    raw: str = ""
    tags: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class EventOut(BaseModel):
    id: str
    timestamp: datetime
    ingested_at: datetime
    source_id: Optional[str] = None
    source_type: str
    host: str
    category: str
    action: str
    outcome: str
    severity: str
    user: str
    src_ip: str
    src_port: Optional[int] = None
    dst_ip: str
    dst_port: Optional[int] = None
    protocol: str
    message: str
    raw: str
    tags: list
    extra: dict

    class Config:
        from_attributes = True


class EventPage(BaseModel):
    total: int
    items: list[EventOut]


# --- Sources ---
class SourceCreate(BaseModel):
    name: str
    type: str = "http"
    description: str = ""


class SourceOut(BaseModel):
    id: str
    name: str
    type: str
    api_key: str
    description: str
    created_at: datetime
    last_seen_at: Optional[datetime] = None
    event_count: int

    class Config:
        from_attributes = True


# --- Rules ---
class RuleIn(BaseModel):
    rule_key: str
    name: str
    description: str = ""
    type: str = "threshold"
    severity: str = "medium"
    mitre: str = ""
    enabled: bool = True
    definition: dict[str, Any] = Field(default_factory=dict)


class RuleOut(BaseModel):
    id: str
    rule_key: str
    name: str
    description: str
    type: str
    severity: str
    mitre: str
    enabled: bool
    definition: dict
    is_builtin: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None
    definition: Optional[dict[str, Any]] = None


# --- Alerts ---
class AlertOut(BaseModel):
    id: str
    rule_id: Optional[str] = None
    rule_key: str
    title: str
    description: str
    severity: str
    status: str
    mitre: str
    group_key: str
    event_ids: list
    context: dict
    created_at: datetime
    updated_at: datetime
    assigned_to: str

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None


class AlertPage(BaseModel):
    total: int
    items: list[AlertOut]


# --- Attack chain / entity timeline ---
class TimelineItem(BaseModel):
    type: str  # "event" | "alert"
    timestamp: datetime
    title: str
    severity: str
    is_anchor: bool = False
    detail: dict[str, Any]


class TimelineOut(BaseModel):
    entity_type: str
    entity_value: str
    window_start: datetime
    window_end: datetime
    mitre_techniques: list[str]
    items: list[TimelineItem]


# --- Stats ---
class DashboardStats(BaseModel):
    total_events_24h: int
    total_events_1h: int
    total_alerts_open: int
    alerts_by_severity: dict[str, int]
    events_by_category: dict[str, int]
    events_timeline: list[dict[str, Any]]
    top_src_ips: list[dict[str, Any]]
    top_hosts: list[dict[str, Any]]
    sources_online: int
