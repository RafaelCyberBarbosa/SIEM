"""Normalizes parsed event dicts and EventIn payloads into Event ORM kwargs,
applies basic enrichment (IP classification, tagging), and persists events."""
from datetime import datetime, timezone
import ipaddress

from sqlalchemy.orm import Session

from app.models import Event, Source

VALID_CATEGORIES = {
    "authentication", "network", "process", "file", "malware",
    "web", "system", "account_management", "other",
}
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_OUTCOMES = {"success", "failure", "unknown"}


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def sanitize(ev: dict) -> dict:
    ev = dict(ev)
    if ev.get("category") not in VALID_CATEGORIES:
        ev["category"] = "other"
    if ev.get("severity") not in VALID_SEVERITIES:
        ev["severity"] = "info"
    if ev.get("outcome") not in VALID_OUTCOMES:
        ev["outcome"] = "unknown"
    ts = ev.get("timestamp")
    if isinstance(ts, str):
        try:
            ev["timestamp"] = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            ev["timestamp"] = datetime.now(timezone.utc)
    elif not isinstance(ts, datetime):
        ev["timestamp"] = datetime.now(timezone.utc)
    if ev["timestamp"].tzinfo is None:
        ev["timestamp"] = ev["timestamp"].replace(tzinfo=timezone.utc)

    tags = list(ev.get("tags") or [])
    src_ip = ev.get("src_ip") or ""
    if src_ip and not _is_private_ip(src_ip):
        if "external-source" not in tags:
            tags.append("external-source")
    ev["tags"] = tags
    ev.setdefault("extra", {})
    return ev


def persist_event(db: Session, ev: dict, source: Source | None, source_type: str) -> Event:
    ev = sanitize(ev)
    event = Event(
        timestamp=ev["timestamp"],
        source_id=source.id if source else None,
        source_type=source_type,
        host=ev.get("host", "") or "",
        category=ev.get("category", "other"),
        action=ev.get("action", "") or "",
        outcome=ev.get("outcome", "unknown"),
        severity=ev.get("severity", "info"),
        user=ev.get("user", "") or "",
        src_ip=ev.get("src_ip", "") or "",
        src_port=ev.get("src_port"),
        dst_ip=ev.get("dst_ip", "") or "",
        dst_port=ev.get("dst_port"),
        protocol=ev.get("protocol", "") or "",
        message=ev.get("message", "") or "",
        raw=ev.get("raw", "") or "",
        tags=ev.get("tags", []),
        extra=ev.get("extra", {}),
    )
    db.add(event)
    if source:
        source.last_seen_at = datetime.now(timezone.utc)
        source.event_count = (source.event_count or 0) + 1
    return event
