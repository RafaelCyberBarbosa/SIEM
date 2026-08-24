"""Periodic purge of events (and orphaned alerts referencing only purged
events) older than EVENT_RETENTION_DAYS, so long-running deployments don't
grow the database unboundedly."""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from app.config import settings
from app.database import SessionLocal
from app.models import Event

logger = logging.getLogger("siem.retention")

RUN_INTERVAL_SECONDS = 6 * 3600  # check every 6 hours


def purge_old_events() -> int:
    if settings.event_retention_days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.event_retention_days)
    db = SessionLocal()
    try:
        deleted = db.query(Event).filter(Event.timestamp < cutoff).delete(synchronize_session=False)
        db.commit()
        return deleted
    finally:
        db.close()


async def run_forever():
    while True:
        try:
            deleted = await asyncio.to_thread(purge_old_events)
            if deleted:
                logger.info("Retention purge: removed %d events older than %d days", deleted, settings.event_retention_days)
        except Exception:
            logger.exception("Retention purge failed")
        await asyncio.sleep(RUN_INTERVAL_SECONDS)
