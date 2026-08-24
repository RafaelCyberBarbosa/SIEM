#!/usr/bin/env python3
"""
UEBA demo: builds a normal login baseline for a user (business-hours logins
from Portugal), then triggers the exact "impossible travel" scenario -
a login from Portugal followed two minutes later by one from Germany, using
real public IPs so GeoIP resolution actually works.

Usage:
    python scripts/generate_ueba_demo.py --siem-url http://localhost:8000 --api-key YOUR_KEY
"""
import argparse
import random
from datetime import datetime, timedelta, timezone

import requests

USER = "joao.silva"
HOST = "vpn-gw"
PT_IP = "85.240.1.50"   # NOS/MEO range, Portugal
DE_IP = "46.4.1.50"     # Hetzner range, Germany


def business_hour_timestamp(days_ago: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    hour = random.randint(8, 18)
    dt = dt.replace(hour=hour, minute=random.randint(0, 59), second=0, microsecond=0)
    return dt.isoformat()


def build_baseline_events(count: int) -> list[dict]:
    events = []
    for i in range(count):
        events.append({
            "timestamp": business_hour_timestamp(days_ago=count - i),
            "host": HOST, "category": "authentication", "action": "login_success",
            "outcome": "success", "severity": "info", "user": USER, "src_ip": PT_IP,
            "message": f"Accepted password for {USER} from {PT_IP} port {40000+i} ssh2",
        })
    return events


def build_impossible_travel_events() -> list[dict]:
    now = datetime.now(timezone.utc)
    return [
        {
            "timestamp": now.isoformat(),
            "host": HOST, "category": "authentication", "action": "login_success",
            "outcome": "success", "severity": "info", "user": USER, "src_ip": PT_IP,
            "message": f"Accepted password for {USER} from {PT_IP} port 44000 ssh2",
        },
        {
            "timestamp": (now + timedelta(minutes=2)).isoformat(),
            "host": HOST, "category": "authentication", "action": "login_success",
            "outcome": "success", "severity": "info", "user": USER, "src_ip": DE_IP,
            "message": f"Accepted password for {USER} from {DE_IP} port 44001 ssh2",
        },
    ]


def send(siem_url: str, api_key: str, events: list[dict]):
    resp = requests.post(
        f"{siem_url}/api/ingest/bulk",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        json=events, timeout=30,
    )
    resp.raise_for_status()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--siem-url", default="http://localhost:8000")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--baseline-logins", type=int, default=15)
    args = parser.parse_args()

    print(f"Sending {args.baseline_logins} baseline logins for '{USER}' from Portugal ({PT_IP})...")
    send(args.siem_url, args.api_key, build_baseline_events(args.baseline_logins))

    print(f"Sending impossible travel scenario: {PT_IP} (Portugal) -> {DE_IP} (Germany), 2 minutes apart...")
    send(args.siem_url, args.api_key, build_impossible_travel_events())

    print(
        "Done. Wait ~15-20s for the UEBA engine cycle, then check the Alerts page - "
        "you should see an 'Impossible Travel Detected' critical alert, and the "
        "'Comportamento' page should show the learned baseline for joao.silva."
    )


if __name__ == "__main__":
    main()
