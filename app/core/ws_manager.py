import asyncio
import json
from datetime import datetime

from fastapi import WebSocket


def _default(o):
    if isinstance(o, datetime):
        return o.isoformat()
    return str(o)


class ConnectionManager:
    def __init__(self):
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            self._connections.discard(ws)

    async def broadcast(self, payload: dict):
        message = json.dumps(payload, default=_default)
        dead = []
        for ws in list(self._connections):
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)


manager = ConnectionManager()

# Thread-safe bridge: the syslog server runs its own event loop in a
# background thread. It schedules broadcasts onto the main app loop via this.
_main_loop: asyncio.AbstractEventLoop | None = None


def set_main_loop(loop: asyncio.AbstractEventLoop):
    global _main_loop
    _main_loop = loop


def broadcast_threadsafe(payload: dict):
    if _main_loop is None:
        return
    asyncio.run_coroutine_threadsafe(manager.broadcast(payload), _main_loop)
