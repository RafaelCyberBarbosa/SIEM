from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Event, User
from app.schemas import EventPage
from app.security import get_current_user

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=EventPage)
def search_events(
    q: Optional[str] = Query(None, description="Full-text search across message/raw/user/host/src_ip"),
    category: Optional[str] = None,
    severity: Optional[str] = None,
    outcome: Optional[str] = None,
    host: Optional[str] = None,
    src_ip: Optional[str] = None,
    user_field: Optional[str] = Query(None, alias="user"),
    source_type: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    query = db.query(Event)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(
            Event.message.ilike(like), Event.raw.ilike(like), Event.user.ilike(like),
            Event.host.ilike(like), Event.src_ip.ilike(like), Event.dst_ip.ilike(like),
        ))
    if category:
        query = query.filter(Event.category == category)
    if severity:
        query = query.filter(Event.severity == severity)
    if outcome:
        query = query.filter(Event.outcome == outcome)
    if host:
        query = query.filter(Event.host.ilike(f"%{host}%"))
    if src_ip:
        query = query.filter(Event.src_ip == src_ip)
    if user_field:
        query = query.filter(Event.user.ilike(f"%{user_field}%"))
    if source_type:
        query = query.filter(Event.source_type == source_type)
    if start:
        query = query.filter(Event.timestamp >= start)
    if end:
        query = query.filter(Event.timestamp <= end)

    total = query.count()
    items = (
        query.order_by(Event.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return EventPage(total=total, items=items)


@router.get("/{event_id}")
def get_event(event_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(Event).filter(Event.id == event_id).first()
