#!/usr/bin/env python3
"""
File Integrity Monitoring (FIM) agent for the SIEM.

Periodically scans a configured list of files/folders, compares the current
snapshot (path -> size + mtime) against the previous one, and reports any
file that was created, modified, or deleted. Pure stdlib, no dependencies,
cross-platform (Windows/Linux/macOS).

The very first run only builds a baseline (no events are sent) - otherwise
every pre-existing file in a watched folder would be reported as "created".

Usage:
    python file_integrity_agent.py --config fim_config.json

Config file (JSON):
{
  "siem_url": "http://localhost:8000",
  "api_key": "your-source-api-key",
  "hostname": "my-workstation",
  "poll_interval_seconds": 5,
  "watch_paths": [
    "C:\\Users\\me\\Desktop",
    "C:\\Windows\\System32\\drivers\\etc\\hosts"
  ],
  "ignore_extensions": [".tmp", ".log", ".swp", ".lock"],
  "max_files": 20000
}
"""
import argparse
import json
import os
import socket
import time
import logging

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("siem-fim-agent")

STATE_FILE = ".fim_state.json"


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"baseline_done": False, "inventory": {}}


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f)


def scan(watch_paths, ignore_extensions, max_files):
    inventory = {}
    for root_path in watch_paths:
        if os.path.isfile(root_path):
            candidates = [root_path]
        elif os.path.isdir(root_path):
            candidates = []
            for dirpath, _dirnames, filenames in os.walk(root_path):
                for name in filenames:
                    candidates.append(os.path.join(dirpath, name))
                    if len(candidates) >= max_files:
                        break
                if len(candidates) >= max_files:
                    break
        else:
            continue

        for path in candidates:
            if any(path.lower().endswith(ext.lower()) for ext in ignore_extensions):
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            inventory[path] = {"size": st.st_size, "mtime": st.st_mtime}
            if len(inventory) >= max_files:
                return inventory
    return inventory


def diff(old_inventory: dict, new_inventory: dict):
    created = [p for p in new_inventory if p not in old_inventory]
    deleted = [p for p in old_inventory if p not in new_inventory]
    modified = [
        p for p in new_inventory
        if p in old_inventory and (
            new_inventory[p]["size"] != old_inventory[p]["size"]
            or new_inventory[p]["mtime"] != old_inventory[p]["mtime"]
        )
    ]
    return created, modified, deleted


def build_events(created, modified, deleted, inventory, hostname):
    events = []
    for path in created:
        info = inventory[path]
        events.append({
            "host": hostname, "category": "file", "action": "file_created", "outcome": "success",
            "severity": "info", "message": f"File created: {path} ({info['size']} bytes)",
            "extra": {"path": path, "size": info["size"]},
        })
    for path in modified:
        info = inventory[path]
        events.append({
            "host": hostname, "category": "file", "action": "file_modified", "outcome": "success",
            "severity": "low", "message": f"File modified: {path} ({info['size']} bytes)",
            "extra": {"path": path, "size": info["size"]},
        })
    for path in deleted:
        events.append({
            "host": hostname, "category": "file", "action": "file_deleted", "outcome": "success",
            "severity": "medium", "message": f"File deleted: {path}",
            "extra": {"path": path},
        })
    return events


def ship_events(siem_url: str, api_key: str, events: list):
    if not events:
        return
    resp = requests.post(
        f"{siem_url}/api/ingest/bulk",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        json=events, timeout=30,
    )
    resp.raise_for_status()


def main():
    parser = argparse.ArgumentParser(description="SIEM file integrity monitoring agent")
    parser.add_argument("--config", required=True, help="Path to JSON config file")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    siem_url = cfg["siem_url"].rstrip("/")
    api_key = cfg["api_key"]
    hostname = cfg.get("hostname") or socket.gethostname()
    poll_interval = cfg.get("poll_interval_seconds", 5)
    watch_paths = cfg["watch_paths"]
    ignore_extensions = cfg.get("ignore_extensions", [".tmp", ".log", ".swp", ".lock"])
    max_files = cfg.get("max_files", 20000)

    state = load_state()
    logger.info("FIM agent starting. Watching %d path(s) as host=%s", len(watch_paths), hostname)

    if not state["baseline_done"]:
        logger.info("Building initial baseline (no events will be sent for this scan)...")
        inventory = scan(watch_paths, ignore_extensions, max_files)
        state["inventory"] = inventory
        state["baseline_done"] = True
        save_state(state)
        logger.info("Baseline complete: %d files tracked.", len(inventory))

    while True:
        time.sleep(poll_interval)
        try:
            new_inventory = scan(watch_paths, ignore_extensions, max_files)
        except Exception:
            logger.exception("Scan failed")
            continue

        created, modified, deleted = diff(state["inventory"], new_inventory)
        if created or modified or deleted:
            events = build_events(created, modified, deleted, new_inventory, hostname)
            try:
                ship_events(siem_url, api_key, events)
                logger.info(
                    "Shipped %d file events (created=%d modified=%d deleted=%d)",
                    len(events), len(created), len(modified), len(deleted),
                )
            except Exception:
                logger.exception("Failed to ship file events")
                continue  # retry the same diff next cycle by not committing the new state

        state["inventory"] = new_inventory
        save_state(state)


if __name__ == "__main__":
    main()
