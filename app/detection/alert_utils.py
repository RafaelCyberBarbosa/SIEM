"""Shared alert creation/dedup logic used by both the rule-based detection
engine and the UEBA behavioral engine, so both raise alerts the same way."""
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import Rule, Alert
from app.core.ws_manager import manager
from app.alerting.notifiers import dispatch_alert_notifications

ALERT_DEDUP_WINDOW_SECONDS = 900  # merge repeated matches into the same open alert for 15 min


def get_or_create_alert(db: Session, rule: Rule, group_key: str, title: str, description: str) -> tuple[Alert, bool]:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=ALERT_DEDUP_WINDOW_SECONDS)
    existing = (
        db.query(Alert)
        .filter(Alert.rule_key == rule.rule_key, Alert.group_key == group_key,
                Alert.status == "open", Alert.updated_at >= cutoff)
        .order_by(Alert.updated_at.desc())
        .first()
    )
    if existing:
        return existing, False
    alert = Alert(
        rule_id=rule.id, rule_key=rule.rule_key, title=title, description=description,
        severity=rule.severity, status="open", mitre=rule.mitre, group_key=group_key,
        event_ids=[], context={},
    )
    db.add(alert)
    return alert, True


async def raise_alert(db: Session, rule: Rule, group_key: str, event_ids: list[str], context: dict,
                       title: str | None = None) -> Alert:
    title = title or (f"{rule.name}" + (f" ({group_key})" if group_key else ""))
    alert, is_new = get_or_create_alert(db, rule, group_key, title, rule.description)
    merged_ids = list(dict.fromkeys((alert.event_ids or []) + event_ids))[-50:]
    alert.event_ids = merged_ids
    alert.context = {**(alert.context or {}), **context}
    db.commit()
    db.refresh(alert)

    await manager.broadcast({
        "type": "alert",
        "data": {
            "id": alert.id, "title": alert.title, "severity": alert.severity,
            "rule_key": alert.rule_key, "status": alert.status,
            "created_at": alert.created_at.isoformat(), "group_key": alert.group_key,
        },
    })
    if is_new:
        await dispatch_alert_notifications(alert)
    return alert
