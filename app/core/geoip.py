"""IP geolocation with local caching. Resolves a public IP to a country code
and approximate coordinates so the UEBA engine can compute travel distance/
speed between logins. Private/reserved IPs are never looked up (there is
nothing to resolve). Results are cached indefinitely in the database, so
each distinct public IP is only ever looked up once even across restarts.

Uses the free ip-api.com endpoint (no API key required for reasonable,
non-commercial request volume). If disabled or unreachable, resolution
simply returns None and callers degrade gracefully (no travel/geo scoring
for that event, other UEBA checks still run)."""
import ipaddress
import logging

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.models import GeoIPCache

logger = logging.getLogger("siem.geoip")


def _is_lookupable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast)


async def resolve_ip(db: Session, ip: str) -> GeoIPCache | None:
    if not ip or not _is_lookupable(ip):
        return None

    cached = db.query(GeoIPCache).filter(GeoIPCache.ip == ip).first()
    if cached:
        return cached if cached.country_code else None

    if not settings.geoip_enabled:
        return None

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,lat,lon"},
            )
            data = resp.json()
    except Exception:
        logger.warning("GeoIP lookup failed for %s", ip)
        return None

    entry = GeoIPCache(ip=ip)
    if data.get("status") == "success":
        entry.country_code = data.get("countryCode", "") or ""
        entry.country_name = data.get("country", "") or ""
        entry.lat = data.get("lat")
        entry.lon = data.get("lon")
    # Cache negative results too (empty country_code) so a bogus/unroutable
    # IP doesn't get looked up again on every single login.
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry if entry.country_code else None
