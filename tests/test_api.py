def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_login_success(client):
    resp = client.post("/api/auth/login", data={"username": "admin", "password": "admin12345"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["role"] == "admin"
    assert "access_token" in body


def test_login_failure(client):
    resp = client.post("/api/auth/login", data={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_events_requires_auth(client):
    resp = client.get("/api/events")
    assert resp.status_code == 401


def test_ingest_and_search_event(client, auth_headers):
    resp = client.post(
        "/api/ingest/event",
        headers={"X-API-Key": "test-ingest-key"},
        json={"category": "authentication", "action": "login_failure", "outcome": "failure",
              "src_ip": "203.0.113.5", "user": "root", "message": "test failed login"},
    )
    assert resp.status_code == 200

    resp = client.get("/api/events?q=root", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert any(ev["user"] == "root" for ev in data["items"])


def test_ingest_bad_api_key_rejected(client):
    resp = client.post(
        "/api/ingest/event", headers={"X-API-Key": "wrong-key"},
        json={"message": "should fail"},
    )
    assert resp.status_code == 401


def test_ssh_bruteforce_triggers_alert(client, auth_headers):
    import time

    events = [
        {"category": "authentication", "action": "login_failure", "outcome": "failure",
         "src_ip": "198.51.100.23", "user": "root", "message": f"Failed password for root from 198.51.100.23 port {40000+i} ssh2"}
        for i in range(6)
    ]
    resp = client.post("/api/ingest/bulk", headers={"X-API-Key": "test-ingest-key"}, json=events)
    assert resp.status_code == 200

    from app.detection.engine import engine as detection_engine
    import asyncio
    asyncio.run(detection_engine.process_new_events())

    resp = client.get("/api/alerts?rule_key=ssh_bruteforce", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1


def test_rules_listed(client, auth_headers):
    resp = client.get("/api/rules", headers=auth_headers)
    assert resp.status_code == 200
    keys = [r["rule_key"] for r in resp.json()]
    assert "ssh_bruteforce" in keys
