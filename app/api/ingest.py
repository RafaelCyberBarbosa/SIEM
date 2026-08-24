from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Source
from app.schemas import EventIn
from app.security import verify_ingest_key
from app.ingestion.normalizer import persist_event
from app.ingestion.parsers import parse_log_line
from app.core.ws_manager import manager
from app.schemas import EventOut

router = APIRouter(prefix="/api/ingest", tags=["ingest"])


class RawLinesIn(BaseModel):
    host: str = ""
    lines: list[str]


async def _persist_and_broadcast(db: Session, ev: dict, source, source_type: str):
    event = persist_event(db, ev, source, source_type)
    db.commit()
    db.refresh(event)
    await manager.broadcast({"type": "event", "data": EventOut.model_validate(event).model_dump()})
    return event


@router.post("/event")
async def ingest_event(payload: EventIn, db: Session = Depends(get_db), source: Source | None = Depends(verify_ingest_key)):
    ev = payload.model_dump()
    event = await _persist_and_broadcast(db, ev, source, source.type if source else "http")
    return {"id": event.id}


@router.post("/bulk")
async def ingest_bulk(payload: list[EventIn], db: Session = Depends(get_db), source: Source | None = Depends(verify_ingest_key)):
    ids = []
    for item in payload:
        event = await _persist_and_broadcast(db, item.model_dump(), source, source.type if source else "http")
        ids.append(event.id)
    return {"ids": ids, "count": len(ids)}


@router.post("/raw")
async def ingest_raw_lines(payload: RawLinesIn, db: Session = Depends(get_db), source: Source | None = Depends(verify_ingest_key)):
    ids = []
    for line in payload.lines:
        parsed = parse_log_line(line, default_host=payload.host)
        event = await _persist_and_broadcast(db, parsed, source, source.type if source else "agent")
        ids.append(event.id)
    return {"ids": ids, "count": len(ids)}
