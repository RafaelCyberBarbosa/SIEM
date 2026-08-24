import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    String, Integer, DateTime, Boolean, JSON, Text, ForeignKey, Float, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="analyst")  # admin, analyst, viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    type: Mapped[str] = mapped_column(String(32), default="http")  # syslog, http, agent-windows, agent-linux, file
    api_key: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=lambda: uuid.uuid4().hex)
    description: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=now)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    source_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("sources.id"), nullable=True, index=True)
    source_type: Mapped[str] = mapped_column(String(32), default="http", index=True)

    host: Mapped[str] = mapped_column(String(255), default="", index=True)
    category: Mapped[str] = mapped_column(String(64), default="other", index=True)  # authentication, network, process, file, malware, web, system, other
    action: Mapped[str] = mapped_column(String(128), default="", index=True)
    outcome: Mapped[str] = mapped_column(String(16), default="unknown", index=True)  # success, failure, unknown
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True)  # info, low, medium, high, critical

    user: Mapped[str] = mapped_column(String(128), default="", index=True)
    src_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16), default="")

    message: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    extra: Mapped[dict] = mapped_column(JSON, default=dict)

    __table_args__ = (
        Index("ix_events_ts_category", "timestamp", "category"),
        Index("ix_events_ts_severity", "timestamp", "severity"),
    )


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    rule_key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    type: Mapped[str] = mapped_column(String(32), default="threshold")  # threshold, match, sequence
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    mitre: Mapped[str] = mapped_column(String(32), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    definition: Mapped[dict] = mapped_column(JSON, default=dict)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    rule_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("rules.id"), nullable=True)
    rule_key: Mapped[str] = mapped_column(String(128), default="")
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open, acknowledged, resolved, closed
    mitre: Mapped[str] = mapped_column(String(32), default="")
    group_key: Mapped[str] = mapped_column(String(255), default="", index=True)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    context: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)
    assigned_to: Mapped[str] = mapped_column(String(64), default="")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    actor: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(128), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class DetectionState(Base):
    """Tracks the last-processed event timestamp for the detection engine."""
    __tablename__ = "detection_state"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(255), default="")


class GeoIPCache(Base):
    """Local cache of IP -> country/coordinates lookups, so the same IP is
    never resolved twice and the SIEM can work offline once warmed up."""
    __tablename__ = "geoip_cache"

    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    country_code: Mapped[str] = mapped_column(String(8), default="")
    country_name: Mapped[str] = mapped_column(String(128), default="")
    lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    lon: Mapped[float | None] = mapped_column(Float, nullable=True)
    resolved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class UserBehaviorProfile(Base):
    """Learned baseline of 'normal' for a single user, used by the UEBA
    engine to score new logins for anomalies (odd hour, new country,
    impossible travel)."""
    __tablename__ = "user_behavior_profiles"

    user: Mapped[str] = mapped_column(String(128), primary_key=True)
    login_count: Mapped[int] = mapped_column(Integer, default=0)
    hour_histogram: Mapped[list] = mapped_column(JSON, default=lambda: [0] * 24)
    known_countries: Mapped[list] = mapped_column(JSON, default=list)
    known_src_ips: Mapped[list] = mapped_column(JSON, default=list)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_src_ip: Mapped[str] = mapped_column(String(64), default="")
    last_login_country: Mapped[str] = mapped_column(String(8), default="")
    last_login_lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_login_lon: Mapped[float | None] = mapped_column(Float, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)
