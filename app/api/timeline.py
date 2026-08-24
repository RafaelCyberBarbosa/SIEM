"""Attack-chain / entity timeline: given an event or alert, reconstruct
everything that happened around the same source IP/host/user in a time
window, so an analyst can see the full story (recon -> initial access ->
persistence -> impact) instead of one isolated alert."""
import ipaddress
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Event, Alert, User
from app.schemas import TimelineOut, TimelineItem
from app.security import get_current_user

router = APIRouter(prefix="/api/timeline", tags=["timeline"])


def resolve_entity(event: Event) -> tuple[str, str] | None:
    if event.src_ip:
        return "src_ip", event.src_ip
    if event.host:
        return "host", event.host
    if event.user:
        return "user", event.user
    return None


def build_timeline(db: Session, entity_type: str, entity_value: str, anchor_ts: datetime,
                    window_minutes: int, anchor_event_id: str | None = None,
                    anchor_alert_id: str | None = None) -> TimelineOut:
    window_start = anchor_ts - timedelta(minutes=window_minutes)
    window_end = anchor_ts + timedelta(minutes=window_minutes)

    event_query = db.query(Event).filter(Event.timestamp >= window_start, Event.timestamp <= window_end)
    if entity_type == "src_ip":
        event_query = event_query.filter(Event.src_ip == entity_value)
    elif entity_type == "host":
        event_query = event_query.filter(Event.host == entity_value)
    else:
        event_query = event_query.filter(Event.user == entity_value)
    events = event_query.order_by(Event.timestamp.asc()).limit(300).all()

    alerts = (
        db.query(Alert)
        .filter(Alert.group_key == entity_value, Alert.created_at >= window_start, Alert.created_at <= window_end)
        .order_by(Alert.created_at.asc())
        .limit(200)
        .all()
    )

    items: list[TimelineItem] = []
    for ev in events:
        items.append(TimelineItem(
            type="event",
            timestamp=ev.timestamp,
            title=f"{ev.category}/{ev.action}" if ev.action else ev.category,
            severity=ev.severity,
            is_anchor=(ev.id == anchor_event_id),
            detail={
                "id": ev.id, "host": ev.host, "user": ev.user, "src_ip": ev.src_ip,
                "message": ev.message, "outcome": ev.outcome, "source_type": ev.source_type,
            },
        ))
    for al in alerts:
        items.append(TimelineItem(
            type="alert",
            timestamp=al.created_at,
            title=al.title,
            severity=al.severity,
            is_anchor=(al.id == anchor_alert_id),
            detail={
                "id": al.id, "rule_key": al.rule_key, "mitre": al.mitre,
                "status": al.status, "description": al.description,
            },
        ))

    items.sort(key=lambda i: i.timestamp)
    mitre = sorted({al.mitre for al in alerts if al.mitre})

    return TimelineOut(
        entity_type=entity_type, entity_value=entity_value,
        window_start=window_start, window_end=window_end,
        mitre_techniques=mitre, items=items,
    )


@router.get("/event/{event_id}", response_model=TimelineOut)
def timeline_from_event(
    event_id: str, window_minutes: int = Query(120, ge=5, le=1440),
    db: Session = Depends(get_db), _=Depends(get_current_user),
):
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    entity = resolve_entity(event)
    if not entity:
        return TimelineOut(
            entity_type="none", entity_value="",
            window_start=event.timestamp, window_end=event.timestamp,
            mitre_techniques=[],
            items=[TimelineItem(
                type="event", timestamp=event.timestamp,
                title=f"{event.category}/{event.action}", severity=event.severity, is_anchor=True,
                detail={"id": event.id, "host": event.host, "user": event.user,
                        "src_ip": event.src_ip, "message": event.message},
            )],
        )
    entity_type, entity_value = entity
    return build_timeline(db, entity_type, entity_value, event.timestamp, window_minutes, anchor_event_id=event.id)


@router.get("/alert/{alert_id}", response_model=TimelineOut)
def timeline_from_alert(
    alert_id: str, window_minutes: int = Query(120, ge=5, le=1440),
    db: Session = Depends(get_db), _=Depends(get_current_user),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    anchor_event = None
    if alert.event_ids:
        anchor_event = db.query(Event).filter(Event.id.in_(alert.event_ids)).order_by(Event.timestamp.desc()).first()

    if anchor_event:
        entity = resolve_entity(anchor_event)
        anchor_ts = anchor_event.timestamp
    elif alert.group_key:
        try:
            ipaddress.ip_address(alert.group_key)
            entity = ("src_ip", alert.group_key)
        except ValueError:
            entity = ("host", alert.group_key)
        anchor_ts = alert.created_at
    else:
        entity = None
        anchor_ts = alert.created_at

    if not entity:
        return TimelineOut(
            entity_type="none", entity_value="", window_start=alert.created_at, window_end=alert.created_at,
            mitre_techniques=[alert.mitre] if alert.mitre else [],
            items=[TimelineItem(
                type="alert", timestamp=alert.created_at, title=alert.title, severity=alert.severity,
                is_anchor=True,
                detail={"id": alert.id, "rule_key": alert.rule_key, "mitre": alert.mitre,
                        "status": alert.status, "description": alert.description},
            )],
        )

    entity_type, entity_value = entity
    return build_timeline(db, entity_type, entity_value, anchor_ts, window_minutes, anchor_alert_id=alert.id)
