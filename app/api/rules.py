from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Rule, User
from app.schemas import RuleIn, RuleOut, RuleUpdate
from app.security import get_current_user, require_role

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("", response_model=list[RuleOut])
def list_rules(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(Rule).order_by(Rule.name.asc()).all()


@router.post("", response_model=RuleOut)
def create_rule(payload: RuleIn, db: Session = Depends(get_db), _=Depends(require_role("admin", "analyst"))):
    if db.query(Rule).filter(Rule.rule_key == payload.rule_key).first():
        raise HTTPException(status_code=409, detail="rule_key already exists")
    if payload.type not in ("threshold", "match", "sequence"):
        raise HTTPException(status_code=400, detail="type must be threshold, match, or sequence")
    rule = Rule(**payload.model_dump(), is_builtin=False)
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.patch("/{rule_id}", response_model=RuleOut)
def update_rule(rule_id: str, payload: RuleUpdate, db: Session = Depends(get_db), _=Depends(require_role("admin", "analyst"))):
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Not found")
    data = payload.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(rule, k, v)
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/{rule_id}")
def delete_rule(rule_id: str, db: Session = Depends(get_db), _=Depends(require_role("admin"))):
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Not found")
    if rule.is_builtin:
        raise HTTPException(status_code=400, detail="Built-in rules cannot be deleted, only disabled")
    db.delete(rule)
    db.commit()
    return {"ok": True}
