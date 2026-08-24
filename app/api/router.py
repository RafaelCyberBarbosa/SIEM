from fastapi import APIRouter

from app.api import auth, users, events, alerts, rules, sources, ingest, stats, ws

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(events.router)
api_router.include_router(alerts.router)
api_router.include_router(rules.router)
api_router.include_router(sources.router)
api_router.include_router(ingest.router)
api_router.include_router(stats.router)
api_router.include_router(ws.router)
