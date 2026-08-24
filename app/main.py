import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.config import settings
from app.database import Base, engine, SessionLocal
from app.models import User
from app.security import hash_password
from app.detection.rules_loader import load_default_rules_into_db
from app.detection.engine import engine as detection_engine
from app.ingestion.syslog_server import start_udp_server, start_tcp_server
from app.core.ws_manager import set_main_loop
from app.core import retention
from app.api.router import api_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("siem")

_background_tasks: list[asyncio.Task] = []
_transports = []


def _bootstrap_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            admin = User(
                username=settings.admin_username,
                email=settings.admin_email,
                password_hash=hash_password(settings.admin_password),
                role="admin",
            )
            db.add(admin)
            db.commit()
            logger.info("Created bootstrap admin user '%s'", settings.admin_username)
        created = load_default_rules_into_db(db)
        if created:
            logger.info("Loaded %d built-in detection rules", created)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _bootstrap_db()
    set_main_loop(asyncio.get_running_loop())

    if settings.syslog_udp_enabled:
        transport = await start_udp_server(settings.syslog_bind_host, settings.syslog_udp_port)
        _transports.append(transport)
    if settings.syslog_tcp_enabled:
        server = await start_tcp_server(settings.syslog_bind_host, settings.syslog_tcp_port)
        _transports.append(server)

    task = asyncio.create_task(detection_engine.run_forever(settings.detection_interval_seconds))
    _background_tasks.append(task)
    _background_tasks.append(asyncio.create_task(retention.run_forever()))

    logger.info("SIEM backend ready.")
    yield

    detection_engine.stop()
    for t in _background_tasks:
        t.cancel()
    for tr in _transports:
        tr.close()


app = FastAPI(title="ZeroDay", version="1.0.0", lifespan=lifespan)
app.include_router(api_router)

app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/")
def root():
    return FileResponse("app/static/index.html")


@app.get("/api/health")
def health():
    return {"status": "ok"}
