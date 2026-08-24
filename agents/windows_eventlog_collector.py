#!/usr/bin/env python3
"""
Windows Event Log collector for the SIEM.

Polls the Security, System, and Application event logs via pywin32 and ships
new events as structured JSON to /api/ingest/event. Requires: pip install pywin32

Usage:
    python windows_eventlog_collector.py --siem-url http://localhost:8000 --api-key KEY [--channels Security,System,Application]

Run as Administrator (the Security log requires elevated privileges to read).
"""
import argparse
import socket
import time
import logging
from datetime import datetime, timezone

import requests

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("siem-winlog-agent")


def read_new_events(channel: str, last_record_number: int):
    hand = win32evtlog.OpenEventLog(None, channel)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = []
    try:
        while True:
            batch = win32evtlog.ReadEventLog(hand, flags, 0)
            if not batch:
                break
            stop = False
            for ev in batch:
                if ev.RecordNumber <= last_record_number:
                    stop = True
                    break
                events.append(ev)
            if stop:
                break
    finally:
        win32evtlog.CloseEventLog(hand)
    events.reverse()
    return events


def event_to_line(ev, channel: str) -> str:
    try:
        inserts = " | ".join(ev.StringInserts) if ev.StringInserts else ""
    except Exception:
        inserts = ""
    ts = ev.TimeGenerated.Format() if hasattr(ev.TimeGenerated, "Format") else str(ev.TimeGenerated)
    return f"[{channel}] EventID: {ev.EventID & 0xFFFF} Source: {ev.SourceName} Time: {ts} Data: {inserts}"


def main():
    parser = argparse.ArgumentParser(description="Windows Event Log -> SIEM collector")
    parser.add_argument("--siem-url", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--channels", default="Security,System,Application")
    parser.add_argument("--poll-interval", type=int, default=5)
    args = parser.parse_args()

    if win32evtlog is None:
        raise SystemExit("pywin32 is required: pip install pywin32")

    hostname = socket.gethostname()
    channels = [c.strip() for c in args.channels.split(",") if c.strip()]
    last_record = {}
    for ch in channels:
        hand = win32evtlog.OpenEventLog(None, ch)
        last_record[ch] = win32evtlog.GetNumberOfEventLogRecords(hand)
        win32evtlog.CloseEventLog(hand)

    logger.info("Windows Event Log collector started for channels: %s", channels)

    while True:
        for ch in channels:
            try:
                events = read_new_events(ch, 0)  # fetch recent, filter below by record number
            except Exception:
                logger.exception("Failed reading channel %s", ch)
                continue
            new_events = [e for e in events if e.RecordNumber > last_record.get(ch, 0)]
            if not new_events:
                continue
            lines = [event_to_line(e, ch) for e in new_events]
            try:
                resp = requests.post(
                    f"{args.siem_url}/api/ingest/raw",
                    headers={"X-API-Key": args.api_key, "Content-Type": "application/json"},
                    json={"host": hostname, "lines": lines},
                    timeout=15,
                )
                resp.raise_for_status()
                logger.info("Shipped %d events from %s", len(lines), ch)
                last_record[ch] = max(e.RecordNumber for e in new_events)
            except Exception:
                logger.exception("Failed to ship events from %s", ch)
        time.sleep(args.poll_interval)


if __name__ == "__main__":
    main()
