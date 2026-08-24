#!/usr/bin/env python3
"""
Linux journald collector for the SIEM.

Streams `journalctl -f` and ships new lines in small batches to the SIEM
ingestion API. Avoids needing the python-systemd bindings by shelling out to
the journalctl CLI, which is present on every systemd-based distro.

Usage:
    python3 linux_journald_collector.py --siem-url http://localhost:8000 --api-key KEY [--unit sshd.service]
"""
import argparse
import socket
import subprocess
import time
import logging

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("siem-journald-agent")


def main():
    parser = argparse.ArgumentParser(description="journald -> SIEM collector")
    parser.add_argument("--siem-url", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--unit", default=None, help="Restrict to a specific systemd unit (optional)")
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--flush-interval", type=float, default=2.0)
    args = parser.parse_args()

    hostname = socket.gethostname()
    cmd = ["journalctl", "-f", "-o", "cat", "-n", "0"]
    if args.unit:
        cmd += ["-u", args.unit]

    logger.info("Starting journald tail: %s", " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, errors="replace")

    buffer = []
    last_flush = time.time()

    def flush():
        nonlocal buffer, last_flush
        if not buffer:
            return
        try:
            resp = requests.post(
                f"{args.siem_url}/api/ingest/raw",
                headers={"X-API-Key": args.api_key, "Content-Type": "application/json"},
                json={"host": hostname, "lines": buffer},
                timeout=15,
            )
            resp.raise_for_status()
            logger.info("Shipped %d lines", len(buffer))
        except Exception:
            logger.exception("Failed to ship %d lines", len(buffer))
        buffer = []
        last_flush = time.time()

    try:
        while True:
            line = proc.stdout.readline()
            if line:
                buffer.append(line.rstrip("\n"))
            if len(buffer) >= args.batch_size or (buffer and time.time() - last_flush > args.flush_interval):
                flush()
            if not line and proc.poll() is not None:
                break
    except KeyboardInterrupt:
        pass
    finally:
        flush()
        proc.terminate()


if __name__ == "__main__":
    main()
