from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Source, User
from app.schemas import SourceCreate, SourceOut
from app.security import get_current_user, require_role

router = APIRouter(prefix="/api/sources", tags=["sources"])


@router.get("", response_model=list[SourceOut])
def list_sources(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(Source).order_by(Source.created_at.desc()).all()


@router.post("", response_model=SourceOut)
def create_source(payload: SourceCreate, db: Session = Depends(get_db), _=Depends(require_role("admin", "analyst"))):
    if db.query(Source).filter(Source.name == payload.name).first():
        raise HTTPException(status_code=409, detail="Source name already exists")
    source = Source(name=payload.name, type=payload.type, description=payload.description)
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


@router.post("/{source_id}/rotate-key", response_model=SourceOut)
def rotate_key(source_id: str, db: Session = Depends(get_db), _=Depends(require_role("admin"))):
    import uuid
    source = db.query(Source).filter(Source.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Not found")
    source.api_key = uuid.uuid4().hex
    db.commit()
    db.refresh(source)
    return source


@router.delete("/{source_id}")
def delete_source(source_id: str, db: Session = Depends(get_db), _=Depends(require_role("admin"))):
    source = db.query(Source).filter(Source.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(source)
    db.commit()
    return {"ok": True}
