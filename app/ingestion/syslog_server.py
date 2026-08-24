"""Async syslog receivers (UDP + TCP, RFC3164/RFC5424/CEF/JSON auto-detected)
that feed parsed events straight into the database and broadcast them live."""
import asyncio
import logging

from app.database import SessionLocal
from app.ingestion.parsers import parse_log_line
from app.ingestion.normalizer import persist_event
from app.core.ws_manager import manager
from app.schemas import EventOut

logger = logging.getLogger("siem.syslog")


def _get_or_create_syslog_source(db):
    from app.models import Source
    source = db.query(Source).filter(Source.name == "syslog-listener").first()
    if not source:
        source = Source(name="syslog-listener", type="syslog", description="Built-in syslog UDP/TCP listener")
        db.add(source)
        db.commit()
        db.refresh(source)
    return source


async def _handle_line(raw: str, peer_host: str):
    if not raw.strip():
        return

    def work():
        db = SessionLocal()
        try:
            source = _get_or_create_syslog_source(db)
            parsed = parse_log_line(raw, default_host=peer_host)
            event = persist_event(db, parsed, source, "syslog")
            db.commit()
            db.refresh(event)
            return EventOut.model_validate(event).model_dump()
        finally:
            db.close()

    try:
        payload = await asyncio.to_thread(work)
        await manager.broadcast({"type": "event", "data": payload})
    except Exception:
        logger.exception("Failed to process syslog line: %s", raw[:200])


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        peer_host = addr[0] if addr else ""
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return
        for line in text.splitlines():
            asyncio.ensure_future(_handle_line(line, peer_host))


async def start_udp_server(host: str, port: int):
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: SyslogUDPProtocol(), local_addr=(host, port)
    )
    logger.info("Syslog UDP listener started on %s:%s", host, port)
    return transport


async def _tcp_client_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    peer_host = peer[0] if peer else ""
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            await _handle_line(line.decode("utf-8", errors="replace"), peer_host)
    except (ConnectionResetError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def start_tcp_server(host: str, port: int):
    server = await asyncio.start_server(_tcp_client_handler, host, port)
    logger.info("Syslog TCP listener started on %s:%s", host, port)
    return server
