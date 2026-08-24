#!/usr/bin/env python3
"""
Cross-platform SIEM file-tail agent.

Watches one or more log files, ships new lines to the SIEM ingestion API
(/api/ingest/raw) in small batches. Remembers its read offset per file in a
local .agent_state.json so it can resume after a restart.

Usage:
    python agent.py --config agent_config.json

Config file (JSON):
{
  "siem_url": "http://localhost:8000",
  "api_key": "your-source-api-key",
  "hostname": "web-server-1",
  "poll_interval_seconds": 2,
  "batch_size": 200,
  "files": [
    "/var/log/auth.log",
    "/var/log/nginx/access.log"
  ]
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
logger = logging.getLogger("siem-agent")

STATE_FILE = ".agent_state.json"


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f)


def ship_lines(siem_url: str, api_key: str, hostname: str, lines: list[str]):
    if not lines:
        return
    resp = requests.post(
        f"{siem_url}/api/ingest/raw",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        json={"host": hostname, "lines": lines},
        timeout=15,
    )
    resp.raise_for_status()


def tail_once(path: str, offset: int) -> tuple[list[str], int]:
    if not os.path.exists(path):
        return [], offset
    size = os.path.getsize(path)
    if size < offset:
        offset = 0  # file was rotated/truncated
    lines = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        for line in f:
            if line.endswith("\n"):
                lines.append(line.rstrip("\n"))
            else:
                # partial last line; stop here and re-read it next time
                break
        offset = f.tell()
    return lines, offset


def main():
    parser = argparse.ArgumentParser(description="SIEM file-tail agent")
    parser.add_argument("--config", required=True, help="Path to JSON config file")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    siem_url = cfg["siem_url"].rstrip("/")
    api_key = cfg["api_key"]
    hostname = cfg.get("hostname") or socket.gethostname()
    poll_interval = cfg.get("poll_interval_seconds", 2)
    batch_size = cfg.get("batch_size", 200)
    files = cfg["files"]

    state = load_state()
    logger.info("Agent starting. Watching %d file(s) as host=%s", len(files), hostname)

    while True:
        for path in files:
            offset = state.get(path, 0)
            try:
                lines, new_offset = tail_once(path, offset)
            except Exception:
                logger.exception("Failed reading %s", path)
                continue
            if lines:
                for i in range(0, len(lines), batch_size):
                    chunk = lines[i:i + batch_size]
                    try:
                        ship_lines(siem_url, api_key, hostname, chunk)
                    except Exception:
                        logger.exception("Failed to ship %d lines from %s", len(chunk), path)
                        new_offset = offset  # retry from previous offset next loop
                        break
                state[path] = new_offset
                logger.info("Shipped %d lines from %s", len(lines), path)
        save_state(state)
        time.sleep(poll_interval)


if __name__ == "__main__":
    main()
