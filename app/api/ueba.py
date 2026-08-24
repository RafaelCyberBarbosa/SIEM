from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import UserBehaviorProfile
from app.schemas import UserProfileOut
from app.security import get_current_user

router = APIRouter(prefix="/api/ueba", tags=["ueba"])


@router.get("/profiles", response_model=list[UserProfileOut])
def list_profiles(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(UserBehaviorProfile).order_by(UserBehaviorProfile.login_count.desc()).all()


@router.get("/profiles/{user}", response_model=UserProfileOut)
def get_profile(user: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    profile = db.query(UserBehaviorProfile).filter(UserBehaviorProfile.user == user).first()
    if not profile:
        raise HTTPException(status_code=404, detail="No behavior profile for this user yet")
    return profile
