#!/usr/bin/env python3
"""
Demo data generator. Sends a realistic mix of normal and malicious traffic
to a running SIEM instance so you can see the dashboard, event search, and
detection rules working end-to-end.

Usage:
    python scripts/generate_sample_logs.py --siem-url http://localhost:8000 --api-key YOUR_INGEST_OR_SOURCE_KEY
"""
import argparse
import random
import time

import requests

USERS = ["alice", "bob", "carol", "dave", "svc-backup", "admin", "root"]
HOSTS = ["web-01", "web-02", "db-01", "app-01", "vpn-gw"]
NORMAL_IPS = ["10.0.0.5", "10.0.0.12", "192.168.1.44", "192.168.1.87"]
ATTACKER_IPS = ["203.0.113.77", "198.51.100.23"]


def gen_normal_events(n):
    events = []
    for _ in range(n):
        kind = random.choice(["login_ok", "web", "process"])
        if kind == "login_ok":
            events.append({
                "host": random.choice(HOSTS), "category": "authentication", "action": "login_success",
                "outcome": "success", "severity": "info", "user": random.choice(USERS),
                "src_ip": random.choice(NORMAL_IPS), "src_port": random.randint(30000, 60000),
                "message": "Accepted password for user from trusted network",
            })
        elif kind == "web":
            events.append({
                "host": random.choice(HOSTS), "category": "web", "action": "GET /index.html",
                "outcome": "success", "severity": "info", "src_ip": random.choice(NORMAL_IPS),
                "message": "GET /index.html -> 200",
            })
        else:
            events.append({
                "host": random.choice(HOSTS), "category": "process", "action": "process_start",
                "outcome": "success", "severity": "info", "user": random.choice(USERS),
                "message": "cron.daily backup job started",
            })
    return events


def gen_ssh_bruteforce():
    ip = random.choice(ATTACKER_IPS)
    host = random.choice(HOSTS)
    events = []
    for _ in range(8):
        events.append({
            "host": host, "category": "authentication", "action": "login_failure",
            "outcome": "failure", "severity": "low", "user": random.choice(["root", "admin", "test"]),
            "src_ip": ip, "src_port": random.randint(30000, 60000),
            "message": f"Failed password for {random.choice(['root','admin','test'])} from {ip} port {random.randint(30000,60000)} ssh2",
        })
    events.append({
        "host": host, "category": "authentication", "action": "login_success", "outcome": "success",
        "severity": "info", "user": "root", "src_ip": ip,
        "message": f"Accepted password for root from {ip} port 44122 ssh2",
    })
    return events


def gen_sql_injection():
    ip = random.choice(ATTACKER_IPS)
    return [{
        "host": "web-01", "category": "web", "action": "GET /login.php", "outcome": "failure",
        "severity": "info", "src_ip": ip,
        "message": "GET /login.php?user=admin'--%20OR%20'1'='1 -> 500",
    }]

def gen_privilege_escalation():
    return [{
        "host": "db-01", "category": "account_management", "action": "user_added_to_privileged_group",
        "outcome": "success", "severity": "high", "user": "bob",
        "message": "usermod: add 'bob' to group 'sudo'",
    }]


def gen_malware_signature():
    return [{
        "host": "app-01", "category": "process", "action": "process_start", "outcome": "success",
        "severity": "critical", "user": "SYSTEM",
        "message": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA (mimikatz.exe detected in command line)",
    }]


def send(siem_url, api_key, events):
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
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--sleep", type=float, default=2.0)
    args = parser.parse_args()

    for i in range(args.rounds):
        batch = gen_normal_events(15)
        roll = random.random()
        if roll < 0.35:
            batch += gen_ssh_bruteforce()
            print("Injecting SSH brute-force pattern...")
        if roll < 0.15:
            batch += gen_sql_injection()
            print("Injecting SQL injection attempt...")
        if roll < 0.1:
            batch += gen_privilege_escalation()
            print("Injecting privilege escalation event...")
        if roll < 0.08:
            batch += gen_malware_signature()
            print("Injecting malware signature event...")

        send(args.siem_url, args.api_key, batch)
        print(f"Round {i+1}/{args.rounds}: sent {len(batch)} events")
        time.sleep(args.sleep)

    print("Done. Open the dashboard to see events/alerts.")


if __name__ == "__main__":
    main()
