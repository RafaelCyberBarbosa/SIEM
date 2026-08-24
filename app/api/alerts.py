from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, Event, User
from app.schemas import AlertOut, AlertPage, AlertUpdate
from app.security import get_current_user, require_role

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=AlertPage)
def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    rule_key: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    query = db.query(Alert)
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)
    if rule_key:
        query = query.filter(Alert.rule_key == rule_key)
    if start:
        query = query.filter(Alert.created_at >= start)
    if end:
        query = query.filter(Alert.created_at <= end)

    total = query.count()
    items = (
        query.order_by(Alert.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return AlertPage(total=total, items=items)


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Not found")
    return alert


@router.get("/{alert_id}/events")
def get_alert_events(alert_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Not found")
    events = db.query(Event).filter(Event.id.in_(alert.event_ids or [])).order_by(Event.timestamp.desc()).all()
    return events


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: str, payload: AlertUpdate, db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst")),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Not found")
    if payload.status is not None:
        if payload.status not in ("open", "acknowledged", "resolved", "closed"):
            raise HTTPException(status_code=400, detail="Invalid status")
        alert.status = payload.status
    if payload.assigned_to is not None:
        alert.assigned_to = payload.assigned_to
    db.commit()
    db.refresh(alert)
    return alert
