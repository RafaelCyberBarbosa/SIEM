import asyncio
from datetime import datetime, timedelta, timezone

from app.detection.ueba import haversine_km, ueba_engine


def test_haversine_km_lisbon_to_berlin():
    # Lisbon ~38.72N -9.14W, Berlin ~52.52N 13.40E -> real distance ~2300km
    dist = haversine_km(38.72, -9.14, 52.52, 13.40)
    assert 2100 < dist < 2500


def test_haversine_km_same_point_is_zero():
    assert haversine_km(38.7, -9.1, 38.7, -9.1) == 0


def test_impossible_travel_triggers_alert(client, auth_headers):
    """Pre-seeds the GeoIP cache (no live network call needed) for a Portuguese
    and a German IP, builds a login baseline, then sends a login from Germany
    two minutes after one from Portugal - which is physically impossible."""
    from app.database import SessionLocal
    from app.models import GeoIPCache

    pt_ip, de_ip, user = "85.240.1.50", "46.4.1.50", "ueba.test.user"

    db = SessionLocal()
    try:
        if not db.query(GeoIPCache).filter(GeoIPCache.ip == pt_ip).first():
            db.add(GeoIPCache(ip=pt_ip, country_code="PT", country_name="Portugal", lat=38.72, lon=-9.14))
        if not db.query(GeoIPCache).filter(GeoIPCache.ip == de_ip).first():
            db.add(GeoIPCache(ip=de_ip, country_code="DE", country_name="Germany", lat=52.52, lon=13.40))
        db.commit()
    finally:
        db.close()

    base_time = datetime.now(timezone.utc) - timedelta(hours=10)
    events = []
    for i in range(5):
        events.append({
            "timestamp": (base_time + timedelta(hours=i)).isoformat(),
            "category": "authentication", "action": "login_success", "outcome": "success",
            "user": user, "src_ip": pt_ip, "message": f"Accepted password for {user} from {pt_ip} ssh2",
        })
    last_pt_time = base_time + timedelta(hours=5)
    events.append({
        "timestamp": last_pt_time.isoformat(),
        "category": "authentication", "action": "login_success", "outcome": "success",
        "user": user, "src_ip": pt_ip, "message": f"Accepted password for {user} from {pt_ip} ssh2",
    })
    events.append({
        "timestamp": (last_pt_time + timedelta(minutes=2)).isoformat(),
        "category": "authentication", "action": "login_success", "outcome": "success",
        "user": user, "src_ip": de_ip, "message": f"Accepted password for {user} from {de_ip} ssh2",
    })

    resp = client.post("/api/ingest/bulk", headers={"X-API-Key": "test-ingest-key"}, json=events)
    assert resp.status_code == 200

    asyncio.run(ueba_engine.process_new_events())

    resp = client.get("/api/alerts?rule_key=ueba_impossible_travel", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    alert = data["items"][0]
    assert alert["severity"] == "critical"
    assert alert["context"]["from_country"] == "PT"
    assert alert["context"]["to_country"] == "DE"
    assert alert["context"]["risk_score"] >= 60

    resp = client.get(f"/api/ueba/profiles/{user}", headers=auth_headers)
    assert resp.status_code == 200
    profile = resp.json()
    assert profile["login_count"] == 7
    assert set(profile["known_countries"]) == {"PT", "DE"}
