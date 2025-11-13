from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from backend_api.database import get_db, User, SessionToken, PasswordResetToken, RecoveryCode, BlacklistedIP
from pydantic import BaseModel
from backend_api.schemas import UserInDB, UserCreate
from backend_api.auth import get_current_user, has_role, get_password_hash, UserRole

class BlacklistRequest(BaseModel):
    ip_address: str
    reason: Optional[str] = None

router = APIRouter()

@router.post("/admin/blacklist/add")
async def add_to_blacklist(
    blacklist_request: BlacklistRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(has_role([UserRole.ADMIN]))
):
    existing_ip = db.query(BlacklistedIP).filter(BlacklistedIP.ip_address == blacklist_request.ip_address).first()
    if existing_ip:
        raise HTTPException(status_code=400, detail="IP address already blacklisted")

    new_blacklisted_ip = BlacklistedIP(
        ip_address=blacklist_request.ip_address,
        reason=blacklist_request.reason
    )
    db.add(new_blacklisted_ip)
    db.commit()
    return {"message": f"IP address {blacklist_request.ip_address} has been blacklisted"}

@router.post("/admin/blacklist/remove")
async def remove_from_blacklist(
    blacklist_request: BlacklistRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(has_role([UserRole.ADMIN]))
):
    blacklisted_ip = db.query(BlacklistedIP).filter(BlacklistedIP.ip_address == blacklist_request.ip_address).first()
    if not blacklisted_ip:
        raise HTTPException(status_code=404, detail="IP address not found in blacklist")

    db.delete(blacklisted_ip)
    db.commit()
    return {"message": f"IP address {blacklist_request.ip_address} has been removed from the blacklist"}

@router.get("/admin/users", response_model=List[UserInDB])
async def get_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(has_role([UserRole.ADMIN])),
    search: Optional[str] = Query(None, description="Search by username"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100)
):
    query = db.query(User)
    if search:
        query = query.filter(User.username.ilike(f"%{search}%"))
    users = query.offset(skip).limit(limit).all()
    return users
