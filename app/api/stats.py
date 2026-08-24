from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Event, Alert, Source
from app.schemas import DashboardStats
from app.security import get_current_user

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("/dashboard", response_model=DashboardStats)
def dashboard(db: Session = Depends(get_db), _=Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    last_1h = now - timedelta(hours=1)

    total_24h = db.query(Event).filter(Event.timestamp >= last_24h).count()
    total_1h = db.query(Event).filter(Event.timestamp >= last_1h).count()
    open_alerts = db.query(Alert).filter(Alert.status == "open").count()

    sev_rows = (
        db.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.status == "open")
        .group_by(Alert.severity)
        .all()
    )
    alerts_by_severity = {s: c for s, c in sev_rows}
    for s in ("info", "low", "medium", "high", "critical"):
        alerts_by_severity.setdefault(s, 0)

    cat_rows = (
        db.query(Event.category, func.count(Event.id))
        .filter(Event.timestamp >= last_24h)
        .group_by(Event.category)
        .all()
    )
    events_by_category = {c: n for c, n in cat_rows}

    # Hourly timeline for the last 24h
    timeline = []
    for i in range(23, -1, -1):
        bucket_start = now - timedelta(hours=i + 1)
        bucket_end = now - timedelta(hours=i)
        count = db.query(Event).filter(Event.timestamp >= bucket_start, Event.timestamp < bucket_end).count()
        timeline.append({"hour": bucket_end.strftime("%H:00"), "count": count})

    top_ips_rows = (
        db.query(Event.src_ip, func.count(Event.id).label("n"))
        .filter(Event.timestamp >= last_24h, Event.src_ip != "")
        .group_by(Event.src_ip)
        .order_by(func.count(Event.id).desc())
        .limit(10)
        .all()
    )
    top_src_ips = [{"src_ip": ip, "count": n} for ip, n in top_ips_rows]

    top_hosts_rows = (
        db.query(Event.host, func.count(Event.id).label("n"))
        .filter(Event.timestamp >= last_24h, Event.host != "")
        .group_by(Event.host)
        .order_by(func.count(Event.id).desc())
        .limit(10)
        .all()
    )
    top_hosts = [{"host": h, "count": n} for h, n in top_hosts_rows]

    sources_online = db.query(Source).filter(Source.last_seen_at >= now - timedelta(minutes=15)).count()

    return DashboardStats(
        total_events_24h=total_24h,
        total_events_1h=total_1h,
        total_alerts_open=open_alerts,
        alerts_by_severity=alerts_by_severity,
        events_by_category=events_by_category,
        events_timeline=timeline,
        top_src_ips=top_src_ips,
        top_hosts=top_hosts,
        sources_online=sources_online,
    )
