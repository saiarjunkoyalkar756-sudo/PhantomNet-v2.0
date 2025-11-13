from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
import os
from enum import Enum
from dotenv import load_dotenv # Import load_dotenv
from passlib.context import CryptContext # Import CryptContext
from jose import JWTError, jwt # Import JWTError and jwt
from datetime import datetime, timedelta
from typing import Optional
import pyotp
import base64
import uuid # Import uuid for JTI generation
import secrets # Import secrets for recovery code generation
import math # Import math for haversine_distance

load_dotenv() # Load environment variables

from backend_api.database import User, SessionLocal, SessionToken, RecoveryCode # Import the User model, SessionLocal, SessionToken, and RecoveryCode
from backend_api.schemas import TokenData # Import TokenData schema

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY_FILE = "/run/secrets/jwt_secret_key"
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, "r") as f:
        SECRET_KEY = f.read().strip()
else:
    SECRET_KEY = os.getenv("JWT_SECRET_KEY")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    USER = "user" # Add a general user role

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# Recovery Code functions
RECOVERY_CODE_LENGTH = 10
RECOVERY_CODE_COUNT = 8

def generate_recovery_code():
    return ''.join(secrets.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(RECOVERY_CODE_LENGTH))

def hash_recovery_code(code: str):
    return pwd_context.hash(code)

def verify_recovery_code(plain_code: str, hashed_code: str):
    return pwd_context.verify(plain_code, hashed_code)

def calculate_anomaly_score(db: Session, user_id: int, ip_address: str, device_fingerprint: str, city: str, country: str) -> float:
    """
    Calculates an anomaly score based on historical session data.
    """
    historical_sessions = db.query(SessionToken).filter(SessionToken.user_id == user_id).order_by(SessionToken.created_at.desc()).limit(10).all()

    if not historical_sessions:
        return 0.0

    score = 0.0
    
    # Check for new IP
    if not any(session.ip == ip_address for session in historical_sessions):
        score += 0.5

    # Check for new device fingerprint
    if device_fingerprint and not any(session.device_fingerprint == device_fingerprint for session in historical_sessions):
        score += 0.3

    # Check for new city
    if city and not any(session.city == city for session in historical_sessions):
        score += 0.2

    return score


import httpx # Import httpx

def create_access_token(
    db: Session,
    user_id: int,
    data: dict,
    expires_delta: Optional[timedelta] = None,
    request: Optional[Request] = None, # Add request to get IP and User-Agent
    device_fingerprint: Optional[str] = None, # Add device_fingerprint
    anomaly_score: Optional[float] = None # Add anomaly_score
):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})

    # Generate JTI
    jti = str(uuid.uuid4())
    to_encode.update({"jti": jti})

    # Add 2FA status to the token
    if "user" in data and data["user"] is not None:
        to_encode["twofa_enabled"] = data["user"].totp_secret is not None
        to_encode["twofa_enforced"] = data["user"].twofa_enforced
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    # Create session token record in the database
    ip_address = request.client.host if request else None
    user_agent = request.headers.get("User-Agent") if request else None

    # Fetch geolocation data
    city = None
    region = None
    country = None
    latitude = None
    longitude = None

    if ip_address and ip_address not in ["127.0.0.1", "localhost"]:
        try:
            # Use a synchronous httpx client here as create_access_token is not async
            response = httpx.get(f"http://ip-api.com/json/{ip_address}")
            response.raise_for_status()
            geo_data = response.json()
            if geo_data.get("status") == "success":
                city = geo_data.get("city")
                region = geo_data.get("regionName")
                country = geo_data.get("country")
                latitude = geo_data.get("lat")
                longitude = geo_data.get("lon")
        except httpx.RequestError as e:
            print(f"Error fetching geolocation for IP {ip_address}: {e}")
        except Exception as e:
            print(f"Unexpected error processing geolocation for IP {ip_address}: {e}")

    session_token = SessionToken(
        jti=jti,
        user_id=user_id,
        created_at=datetime.utcnow(),
        expires_at=expire,
        ip=ip_address,
        user_agent=user_agent,
        device_fingerprint=device_fingerprint, # Add device fingerprint
        anomaly_score=anomaly_score, # Add anomaly score
        is_valid=True,
        city=city,
        region=region,
        country=country,
        latitude=latitude,
        longitude=longitude
    )
    db.add(session_token)
    db.commit()
    db.refresh(session_token)

    return encoded_jwt

def generate_totp_secret():
    return base64.b32encode(os.urandom(10)).decode('utf-8')

def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db: Session, username: str, password: str, totp_code: Optional[str] = None, recovery_code: Optional[str] = None):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None, None # Return None for user and None for status

    # Check for 2FA enforcement or if user has 2FA enabled
    if user.twofa_enforced or user.totp_secret:
        if totp_code:
            if not user.totp_secret or not verify_totp_code(user.totp_secret, totp_code):
                return None, None # Invalid TOTP code, return None for user and None for status
        elif recovery_code:
            # Verify recovery code
            recovery_record = db.query(RecoveryCode).filter(
                RecoveryCode.user_id == user.id,
                RecoveryCode.used_at == None # Not yet used
            ).first()
            if not recovery_record or not verify_recovery_code(recovery_code, recovery_record.code_hash):
                return None, None # Invalid recovery code, return None for user and None for status
            
            # Mark recovery code as used
            recovery_record.used_at = datetime.utcnow()
            db.commit()
        else:
            # If 2FA is required but no code is provided, return a special status
            return user, "2FA_REQUIRED" # Return user object and 2FA_REQUIRED status

    return user, None # Return user object and None for status

async def get_current_user(request: Request, db: Session = Depends(lambda: SessionLocal())):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_role: str = payload.get("role") # Get user role from token
        jti: str = payload.get("jti") # Get JTI from token
        twofa_enabled: bool = payload.get("twofa_enabled", False)
        twofa_enforced: bool = payload.get("twofa_enforced", False)

        if username is None or user_role is None or jti is None:
            raise credentials_exception

        # Validate session token from database
        session_record = db.query(SessionToken).filter(SessionToken.jti == jti).first()
        if not session_record or not session_record.is_valid or session_record.revoked_at or session_record.expires_at < datetime.utcnow():
            raise credentials_exception

        token_data = TokenData(username=username, role=user_role, twofa_enabled=twofa_enabled, twofa_enforced=twofa_enforced)
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

def has_role(required_roles: list[UserRole]):
    async def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user
    return role_checker