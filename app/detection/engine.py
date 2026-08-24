"""Detection engine: periodically scans newly ingested events against the
enabled rule set (threshold, match, sequence) and raises/updates alerts."""
import asyncio
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Event, Rule, Alert, DetectionState
from app.core.ws_manager import manager
from app.alerting.notifiers import dispatch_alert_notifications

logger = logging.getLogger("siem.detection")

CHECKPOINT_KEY = "last_event_ts"
ALERT_DEDUP_WINDOW_SECONDS = 900  # merge repeated matches into the same open alert for 15 min


def _event_to_dict(ev: Event) -> dict:
    return {
        "id": ev.id, "timestamp": ev.timestamp, "host": ev.host, "category": ev.category,
        "action": ev.action, "outcome": ev.outcome, "severity": ev.severity, "user": ev.user,
        "src_ip": ev.src_ip, "src_port": ev.src_port, "dst_ip": ev.dst_ip, "dst_port": ev.dst_port,
        "protocol": ev.protocol, "message": ev.message, "raw": ev.raw, "tags": ev.tags, "extra": ev.extra,
    }


def matches_filter(ev: dict, filt: dict) -> bool:
    if not filt:
        return True
    for key, expected in filt.items():
        if key == "message_contains":
            if expected.lower() not in (ev.get("message") or "").lower():
                return False
        elif key == "message_contains_any":
            msg = (ev.get("message") or "").lower()
            if not any(s.lower() in msg for s in expected):
                return False
        elif isinstance(expected, list):
            if ev.get(key) not in expected:
                return False
        else:
            if ev.get(key) != expected:
                return False
    return True


class DetectionEngine:
    def __init__(self):
        self._threshold_state: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
        self._sequence_state: dict[str, dict[str, datetime]] = defaultdict(dict)
        self._running = False

    def _get_checkpoint(self, db: Session) -> datetime:
        row = db.query(DetectionState).filter(DetectionState.key == CHECKPOINT_KEY).first()
        if row and row.value:
            try:
                return datetime.fromisoformat(row.value)
            except ValueError:
                pass
        return datetime.now(timezone.utc) - timedelta(minutes=5)

    def _set_checkpoint(self, db: Session, ts: datetime):
        row = db.query(DetectionState).filter(DetectionState.key == CHECKPOINT_KEY).first()
        if not row:
            row = DetectionState(key=CHECKPOINT_KEY, value=ts.isoformat())
            db.add(row)
        else:
            row.value = ts.isoformat()
        db.commit()

    def _get_or_create_alert(self, db: Session, rule: Rule, group_key: str, title: str, description: str) -> tuple[Alert, bool]:
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

    async def _raise_alert(self, db: Session, rule: Rule, group_key: str, event_ids: list[str], context: dict):
        title = f"{rule.name}" + (f" ({group_key})" if group_key else "")
        alert, is_new = self._get_or_create_alert(db, rule, group_key, title, rule.description)
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

    async def _eval_threshold(self, db: Session, rule: Rule, ev: dict):
        d = rule.definition or {}
        if not matches_filter(ev, d.get("filter", {})):
            return
        group_field = d.get("group_by")
        group_val = str(ev.get(group_field, "")) if group_field else "__all__"
        if group_field and not group_val:
            return
        window = timedelta(seconds=d.get("window_seconds", 60))
        threshold = d.get("threshold", 5)

        dq = self._threshold_state[rule.rule_key][group_val]
        dq.append((ev["timestamp"], ev["id"]))
        cutoff = ev["timestamp"] - window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        if len(dq) >= threshold:
            event_ids = [e[1] for e in dq]
            await self._raise_alert(
                db, rule, group_val, event_ids,
                {"count": len(dq), "window_seconds": d.get("window_seconds"), "group_by": group_field, "group_value": group_val},
            )
            dq.clear()

    async def _eval_match(self, db: Session, rule: Rule, ev: dict):
        d = rule.definition or {}
        if not matches_filter(ev, d.get("filter", {})):
            return
        group_val = ev.get("src_ip") or ev.get("host") or ev.get("user") or ""
        await self._raise_alert(db, rule, group_val, [ev["id"]], {"matched_event": {k: str(v) for k, v in ev.items() if k != "raw"}})

    async def _eval_sequence(self, db: Session, rule: Rule, ev: dict):
        d = rule.definition or {}
        steps = d.get("steps", [])
        if len(steps) != 2:
            return
        group_field = d.get("group_by", "src_ip")
        group_val = str(ev.get(group_field, ""))
        if not group_val:
            return
        window = timedelta(seconds=d.get("window_seconds", 300))
        state = self._sequence_state[rule.rule_key]

        if matches_filter(ev, steps[0]):
            state[group_val] = ev["timestamp"]
        elif matches_filter(ev, steps[1]) and group_val in state:
            if ev["timestamp"] - state[group_val] <= window:
                await self._raise_alert(
                    db, rule, group_val, [ev["id"]],
                    {"sequence": "step1->step2", "group_by": group_field, "group_value": group_val},
                )
                del state[group_val]

    async def process_new_events(self):
        db = SessionLocal()
        try:
            checkpoint = self._get_checkpoint(db)
            # Checkpointing on ingested_at (server-assigned, monotonic) rather than the
            # event's self-reported timestamp keeps the engine from stalling forever if a
            # source ever sends a bogus/future-dated timestamp.
            events = (
                db.query(Event)
                .filter(Event.ingested_at > checkpoint)
                .order_by(Event.ingested_at.asc())
                .limit(5000)
                .all()
            )
            if not events:
                return

            rules = db.query(Rule).filter(Rule.enabled == True).all()  # noqa: E712
            for ev_row in events:
                ev = _event_to_dict(ev_row)
                for rule in rules:
                    try:
                        if rule.type == "threshold":
                            await self._eval_threshold(db, rule, ev)
                        elif rule.type == "match":
                            await self._eval_match(db, rule, ev)
                        elif rule.type == "sequence":
                            await self._eval_sequence(db, rule, ev)
                    except Exception:
                        logger.exception("Rule %s failed on event %s", rule.rule_key, ev.get("id"))

            self._set_checkpoint(db, events[-1].ingested_at)
        finally:
            db.close()

    async def run_forever(self, interval_seconds: int):
        self._running = True
        logger.info("Detection engine started (interval=%ss)", interval_seconds)
        while self._running:
            try:
                await self.process_new_events()
            except Exception:
                logger.exception("Detection engine iteration failed")
            await asyncio.sleep(interval_seconds)

    def stop(self):
        self._running = False


engine = DetectionEngine()
