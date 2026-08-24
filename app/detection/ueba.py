"""User and Entity Behavior Analytics (UEBA).

Instead of static rules, this engine learns a per-user baseline (which hours
of day they normally log in, which countries they normally log in from) and
scores new logins against it:

  - Impossible travel: the same user authenticated from two countries in
    less time than physically possible to travel between them.
  - New country: a login from a country never seen for that user before.
  - Anomalous hour: a login at a time of day statistically unusual for
    that user, once enough history exists to know what's "usual".

All three checks are backed by editable Rule rows (type="behavioral") so
they can be tuned or disabled from the same Rules UI as everything else -
their `definition` JSON holds the thresholds instead of a filter.
"""
import asyncio
import logging
import math
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Event, Rule, UserBehaviorProfile, DetectionState
from app.core.geoip import resolve_ip
from app.detection.alert_utils import raise_alert

logger = logging.getLogger("siem.ueba")

CHECKPOINT_KEY = "last_ueba_event_ts"

RULE_IMPOSSIBLE_TRAVEL = "ueba_impossible_travel"
RULE_NEW_COUNTRY = "ueba_new_country_login"
RULE_ANOMALOUS_HOUR = "ueba_anomalous_login_time"
UEBA_RULE_KEYS = [RULE_IMPOSSIBLE_TRAVEL, RULE_NEW_COUNTRY, RULE_ANOMALOUS_HOUR]


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


class UEBAEngine:
    def __init__(self):
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
            db.add(DetectionState(key=CHECKPOINT_KEY, value=ts.isoformat()))
        else:
            row.value = ts.isoformat()
        db.commit()

    async def _process_login(self, db: Session, ev: Event, rules: dict[str, Rule]):
        profile = db.query(UserBehaviorProfile).filter(UserBehaviorProfile.user == ev.user).first()
        if not profile:
            profile = UserBehaviorProfile(user=ev.user)
            db.add(profile)
            db.flush()

        geo = await resolve_ip(db, ev.src_ip) if ev.src_ip else None
        hour = ev.timestamp.astimezone(timezone.utc).hour

        # --- Impossible travel: compare against the immediately previous login ---
        rule = rules.get(RULE_IMPOSSIBLE_TRAVEL)
        if (rule and rule.enabled and geo and geo.lat is not None
                and profile.last_login_lat is not None and profile.last_login_at
                and profile.login_count >= (rule.definition or {}).get("min_history_logins", 5)):
            if profile.last_login_country and geo.country_code and profile.last_login_country != geo.country_code:
                minutes = max((ev.timestamp - profile.last_login_at).total_seconds() / 60.0, 0.01)
                dist_km = haversine_km(profile.last_login_lat, profile.last_login_lon, geo.lat, geo.lon)
                required_kmh = dist_km / (minutes / 60.0)
                max_speed = (rule.definition or {}).get("max_speed_kmh", 900)
                if required_kmh > max_speed:
                    risk = min(99, int(60 + min(39, (required_kmh / max_speed) * 10)))
                    await raise_alert(
                        db, rule, ev.user, [ev.id],
                        {
                            "risk_score": risk,
                            "from_country": profile.last_login_country, "to_country": geo.country_code,
                            "from_ip": profile.last_login_src_ip, "to_ip": ev.src_ip,
                            "distance_km": round(dist_km, 1), "minutes_between_logins": round(minutes, 2),
                            "required_speed_kmh": round(required_kmh, 1), "max_plausible_speed_kmh": max_speed,
                        },
                        title=f"Impossible Travel Detected ({ev.user}) — risco {risk}",
                    )

        # --- New country for this user ---
        rule = rules.get(RULE_NEW_COUNTRY)
        if (rule and rule.enabled and geo and geo.country_code
                and profile.login_count >= (rule.definition or {}).get("min_history_logins", 10)
                and geo.country_code not in (profile.known_countries or [])):
            await raise_alert(
                db, rule, ev.user, [ev.id],
                {"country": geo.country_code, "country_name": geo.country_name, "src_ip": ev.src_ip,
                 "known_countries": profile.known_countries},
            )

        # --- Anomalous hour of day for this user ---
        rule = rules.get(RULE_ANOMALOUS_HOUR)
        min_hist = (rule.definition or {}).get("min_history_logins", 15) if rule else 0
        if rule and rule.enabled and profile.login_count >= min_hist:
            hist = profile.hour_histogram or [0] * 24
            total = sum(hist) or 1
            freq = hist[hour] / total
            if freq <= (rule.definition or {}).get("min_hour_frequency", 0.03):
                await raise_alert(
                    db, rule, ev.user, [ev.id],
                    {"hour_utc": hour, "historical_frequency": round(freq, 4),
                     "logins_observed": profile.login_count},
                )

        # --- Update / learn the profile from this login ---
        hist = list(profile.hour_histogram or [0] * 24)
        hist[hour] += 1
        profile.hour_histogram = hist
        profile.login_count = (profile.login_count or 0) + 1
        if geo and geo.country_code:
            known = list(profile.known_countries or [])
            if geo.country_code not in known:
                known.append(geo.country_code)
            profile.known_countries = known
            profile.last_login_country = geo.country_code
            profile.last_login_lat = geo.lat
            profile.last_login_lon = geo.lon
        profile.last_login_at = ev.timestamp
        if ev.src_ip:
            profile.last_login_src_ip = ev.src_ip
            known_ips = list(profile.known_src_ips or [])
            if ev.src_ip not in known_ips:
                known_ips.append(ev.src_ip)
            profile.known_src_ips = known_ips[-20:]
        db.commit()

    async def process_new_events(self):
        db = SessionLocal()
        try:
            checkpoint = self._get_checkpoint(db)
            events = (
                db.query(Event)
                .filter(Event.ingested_at > checkpoint, Event.category == "authentication",
                        Event.action == "login_success", Event.user != "")
                .order_by(Event.ingested_at.asc())
                .limit(2000)
                .all()
            )

            # Advance the checkpoint even when there's nothing to learn from, otherwise
            # a quiet period followed by a burst of non-login events would force this
            # query to rescan them every cycle.
            latest = (
                db.query(Event.ingested_at)
                .filter(Event.ingested_at > checkpoint)
                .order_by(Event.ingested_at.desc())
                .first()
            )

            if events:
                rules = {r.rule_key: r for r in db.query(Rule).filter(Rule.rule_key.in_(UEBA_RULE_KEYS)).all()}
                for ev in events:
                    try:
                        await self._process_login(db, ev, rules)
                    except Exception:
                        logger.exception("UEBA processing failed for event %s", ev.id)

            if latest:
                self._set_checkpoint(db, latest[0])
        finally:
            db.close()

    async def run_forever(self, interval_seconds: int):
        self._running = True
        logger.info("UEBA engine started (interval=%ss)", interval_seconds)
        while self._running:
            try:
                await self.process_new_events()
            except Exception:
                logger.exception("UEBA engine iteration failed")
            await asyncio.sleep(interval_seconds)

    def stop(self):
        self._running = False


ueba_engine = UEBAEngine()
