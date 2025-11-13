from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
import os
from dotenv import load_dotenv
from datetime import timedelta, datetime # Import timedelta and datetime
import sys

load_dotenv()
import json
import asyncio
import httpx
import logging
from loguru import logger # Import loguru logger

from backend_api.database import User, SessionLocal, create_db_and_tables, SessionToken, PasswordResetToken, AttackLog, BlacklistedIP # Import User, SessionLocal, create_db_and_tables, SessionToken, PasswordResetToken, AttackLog
from backend_api.schemas import UserCreate, UserInDB, Token, TokenData, PasswordResetRequest, PasswordResetConfirm, RecoveryCodeResponse, TwoFACode, TwoFAChallenge, MFARequiredResponse, SecurityAlert, Webhook, AttackSimulation, LoginRequest
# from backend_api.analyzer.neural_threat_brain import brain
from backend_api.auth import ( # Import auth functions
    generate_totp_secret,
    verify_totp_code,
    authenticate_user,
    get_current_user,
    get_password_hash,
    create_access_token,
    get_user,
    UserRole,
    has_role,
    SECRET_KEY, # Import SECRET_KEY
    ALGORITHM, # Import ALGORITHM
    generate_recovery_code,
    hash_recovery_code,
    verify_recovery_code,
    RECOVERY_CODE_COUNT, # Import RECOVERY_CODE_COUNT
    calculate_anomaly_score # Import calculate_anomaly_score
)
from pydantic import BaseModel, Field, validator # Import BaseModel, Field, validator
import redis # Import redis
from backend_api.api_gateway.api_ecosystem import router as api_ecosystem_router # Import api_ecosystem_router
from backend_api.admin import router as admin_router
from backend_api.agent_api import router as agent_router # Import admin_router
from backend_api.orchestrator_api import router as orchestrator_router
from backend_api.blockchain_service.blockchain import Blockchain
from starlette.datastructures import URL # Import URL
from uuid import uuid4 # Import uuid4
from backend_api.email_service import send_reset_email # Import send_reset_email
from backend_api.health_monitor import monitor_health # Import health monitor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger.remove() # Remove default logger
logger.add(sys.stderr, format="{time} {level} {message}", level="INFO") # Add basic console logger
logger.add("file.log", rotation="10 MB", compression="zip", serialize=True) # Add file logger with JSON serialization
logger.add("behavioral_data.log", rotation="10 MB", compression="zip", serialize=True, filter=lambda record: "behavioral_data" in record["extra"]) # Add behavioral data logger

app = FastAPI()

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Create database tables on startup
@app.on_event("startup")
async def startup_event():
    create_db_and_tables()
    logger.info("Database tables created/checked.") # Log startup event
    # Start the health monitoring in the background
    asyncio.create_task(monitor_health())
    logger.info("Health monitoring started in background.")

# Initialize Redis client
redis_client = redis.Redis(host='localhost', port=6379, db=0)

class TransactionData(BaseModel):
    ip: str = Field(..., description="IP address of the attacking entity")
    port: int = Field(..., ge=1, le=65535, description="Port number involved in the attack")
    data: str = Field(..., min_length=1, max_length=2048, description="Raw attack data or payload")

    @validator('ip')
    def validate_ip_address(cls, v):
        # Basic IP address validation (can be expanded for IPv6 or more strict checks)
        parts = v.split('.')
        if len(parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            raise ValueError('Invalid IP address format')
        return v

class LogEntryData(BaseModel):
    ip: str = Field(..., description="IP address from the log entry")
    port: int = Field(..., ge=0, le=65535, description="Port from the log entry")
    data: str = Field(..., min_length=1, description="Raw log data")

class AnomalyAlert(BaseModel):
    log_id: int
    ip: str
    port: int
    data: str
    timestamp: str
    anomaly_score: float
    attack_type: str
    confidence_score: float

class ThreatVerifiedAlert(BaseModel):
    log_id: int
    ip: str
    message: str

class BlacklistedAlert(BaseModel):
    ip: str
    message: str

class CopilotContext(BaseModel):
    user_role: str
    company_policy: str

class AttackEvent(BaseModel):
    log_id: int
    attack_type: str
    source_ip: str
    payload: str
    twin_instance_id: str | None = None

class ChatbotQuery(BaseModel):
    persona: str = "analyst"
    context: CopilotContext
    attack_event: AttackEvent
    query: str

class HoneypotControl(BaseModel):
    action: str = Field(..., description="Action to perform: 'start' or 'stop'")
    port: int = Field(..., ge=1, le=65535, description="Port number for the honeypot")

class SimulateAttack(BaseModel):
    ip: str = Field(..., description="IP address for simulation")
    port: int = Field(..., ge=1, le=65535, description="Port for simulation")
    data: str = Field(..., min_length=1, description="Data for simulation")

clients = set() # Store active WebSocket connections


# CORS middleware to allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost"], # Allow only the frontend development server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RATE_LIMIT_THRESHOLD = 100  # requests
RATE_LIMIT_WINDOW = 60  # seconds

BAD_USER_AGENTS = [
    "sqlmap",
    "nmap",
    "nikto",
    "dirb",
    "wpscan",
    "masscan",
    "zgrab",
    "gobuster",
    "dirbuster",
    "hydra",
    "burpsuite",
]

@app.middleware("http")
async def blacklist_middleware(request: Request, call_next):
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "").lower()

    # Check for bad user agents
    for bad_agent in BAD_USER_AGENTS:
        if bad_agent in user_agent:
            logger.warning(f"Blocked request from blacklisted user agent: {user_agent} from IP: {ip}")
            return JSONResponse(status_code=403, content={"detail": "User agent is blacklisted"})

    db = SessionLocal()
    blacklisted_ip = db.query(BlacklistedIP).filter(BlacklistedIP.ip_address == ip).first()
    db.close()
    if blacklisted_ip:
        logger.warning(f"Blocked request from blacklisted IP: {ip}")
        return JSONResponse(status_code=403, content={"detail": "IP address is blacklisted"})
    response = await call_next(request)
    return response

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    ip = request.client.host
    key = f"rate_limit:{ip}"

    # Use a pipeline to execute commands atomically
    pipe = redis_client.pipeline()
    pipe.incr(key)
    pipe.expire(key, RATE_LIMIT_WINDOW)
    request_count, _ = pipe.execute()

    if request_count > RATE_LIMIT_THRESHOLD:
        logger.warning(f"Rate limit exceeded for IP: {ip}")
        return JSONResponse(status_code=429, content={"detail": "Too Many Requests"})

    response = await call_next(request)
    return response

# @app.middleware("http")
# async def csrf_middleware(request: Request, call_next):
#     if request.method in ["POST", "PUT", "DELETE"]:
#         csrf_token = request.headers.get("X-CSRF-Token")
#         # In a real implementation, you would validate this token against a server-generated one
#         # For now, we'll just check for its presence as a placeholder.
#         if not csrf_token:
#             raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing")
CONFIG_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "phantomnet_agent", "config.json")

app.include_router(api_ecosystem_router, prefix="/api/v1/enterprise", tags=["Enterprise API"])
app.include_router(admin_router, prefix="/api", tags=["Admin"])
app.include_router(agent_router, prefix="/api", tags=["Agents"])
app.include_router(orchestrator_router, prefix="/api", tags=["Orchestrator"])

def get_blockchain(db: Session = Depends(get_db)):
    return Blockchain(db)

@app.post("/register", response_model=UserInDB)
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user(db, username=user.username)
    if db_user:
        logger.warning(f"Attempted to register existing user with ID: {db_user.id}") # Log user ID
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, hashed_password=hashed_password, role=user.role, twofa_enforced=False) # Default to False
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    logger.info(f"User registered with ID: {db_user.id} and role {db_user.role}") # Log user ID
    return db_user

@app.post("/token", response_model=Token)
async def login_for_access_token(login_request: LoginRequest, db: Session = Depends(get_db), request: Request = Request):
    user, auth_status = authenticate_user(db, login_request.username, login_request.password, login_request.totp_code, login_request.recovery_code)
    
    if auth_status == "2FA_REQUIRED":
        logger.info(f"2FA required for user ID: {user.id}")
        # Generate a temporary challenge ID for the 2FA challenge
        challenge_id = str(uuid4())
        # Store challenge_id and user_id in Redis with a short expiry
        redis_client.setex(f"2fa_challenge:{challenge_id}", 300, str(user.id)) # 5 minutes expiry, store user.id as string
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"message": "2FA required", "detail": "Two-factor authentication is required.", "mfa_required": True, "challenge_id": challenge_id}
        )
    if not user: # This covers cases where authentication failed or invalid 2FA code was provided
        logger.warning(f"Failed login attempt for username: {login_request.username}") # Consider hashing username for PII redaction
        # Decrease trust score for failed login
        failed_user = get_user(db, login_request.username)
        if failed_user:
            failed_user.trust_score = max(0, failed_user.trust_score - 5) # Decrease by 5, min 0
            db.commit()
            db.refresh(failed_user)
            logger.info(f"Trust score for user ID: {failed_user.id} decreased to {failed_user.trust_score} due to failed login.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password or invalid 2FA code",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Perform session anomaly check
    ip_address = request.client.host if request else None
    device_fingerprint = login_request.device_fingerprint

    # For anomaly detection, we need the geo data of the current login.
    city, region, country, latitude, longitude = None, None, None, None, None
    if ip_address and ip_address not in ["127.0.0.1", "localhost"]:
        try:
            geo_response = httpx.get(f"http://ip-api.com/json/{ip_address}")
            geo_response.raise_for_status()
            geo_data = geo_response.json()
            if geo_data.get("status") == "success":
                city = geo_data.get("city")
                region = geo_data.get("regionName")
                country = geo_data.get("country")
                latitude = geo_data.get("lat")
                longitude = geo_data.get("lon")
        except httpx.RequestError as e:
            logger.error(f"Error fetching geolocation for IP {ip_address} during anomaly check: {e}")
        except Exception as e:
            logger.error(f"Unexpected error processing geolocation for IP {ip_address} during anomaly check: {e}")

    anomaly_score = calculate_anomaly_score(db, user.id, ip_address, device_fingerprint, city, country)

    # Log anonymized behavioral data
    logger.bind(behavioral_data=True).info({
        "anomaly_score": anomaly_score,
        "ip_address": ip_address,
        "device_fingerprint": device_fingerprint,
        "city": city,
        "country": country
    })

    if anomaly_score > 0.7:
        logger.warning(f"Session anomaly detected for user ID: {user.id} from IP: {ip_address}. Anomaly score: {anomaly_score}. Revoking session.")
        # Significantly decrease trust score for session anomaly
        user.trust_score = max(0, user.trust_score - 20) # Decrease by 20, min 0
        db.query(SessionToken).filter(SessionToken.user_id == user.id).update(
            {"is_valid": False, "revoked_at": datetime.utcnow()}
        )
        db.commit()
        db.refresh(user)
        logger.info(f"Trust score for user ID: {user.id} decreased to {user.trust_score} due to session anomaly.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session anomaly detected. All sessions revoked. Please log in again."
        )
    
    # Increase trust score for successful login
    user.trust_score = min(100, user.trust_score + 1) # Increase by 1, max 100
    db.commit()
    db.refresh(user)
    logger.info(f"Trust score for user ID: {user.id} increased to {user.trust_score} due to successful login.")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        db=db,
        user_id=user.id,
        data={"sub": user.username, "role": user.role, "user": user},
        expires_delta=access_token_expires,
        request=request,
        device_fingerprint=login_request.device_fingerprint,
        anomaly_score=anomaly_score
    )
    response = JSONResponse(content={"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="Lax", # Or "Strict" depending on your needs
        secure=True, # Only send cookie over HTTPS
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60, # Convert minutes to seconds
        expires=access_token_expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
    )
    logger.info(f"User logged in with ID: {user.id}") # Log user ID
    return response

@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie(key="access_token")
    logger.info("User logged out by clearing cookie.") # Use logger
    return {"message": "Successfully logged out"}

@app.get("/sessions", dependencies=[Depends(get_current_user)])
async def get_sessions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sessions = db.query(SessionToken).filter(
        SessionToken.user_id == current_user.id,
        SessionToken.is_valid == True,
        SessionToken.expires_at > datetime.utcnow()
    ).all()
    return [
        {
            "jti": session.jti,
            "created_at": session.created_at,
            "expires_at": session.expires_at,
            "ip": session.ip,
            "user_agent": session.user_agent,
        }
        for session in sessions
    ]

@app.post("/sessions/revoke", dependencies=[Depends(get_current_user)])
async def revoke_session(
    jti: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    session_to_revoke = db.query(SessionToken).filter(
        SessionToken.jti == jti,
        SessionToken.user_id == current_user.id,
        SessionToken.is_valid == True
    ).first()

    if not session_to_revoke:
        raise HTTPException(status_code=404, detail="Session not found or already revoked")

    session_to_revoke.is_valid = False
    session_to_revoke.revoked_at = datetime.utcnow()
    db.commit()
    logger.info(f"Session {jti} revoked for user ID: {current_user.id}") # Add logging
    return {"message": "Session revoked successfully"}

@app.post("/sessions/revoke_all", dependencies=[Depends(get_current_user)])
async def revoke_all_sessions(
    exclude_current: bool = True,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = Request # To get the current JTI if exclude_current is True
):
    # Get current JTI from the request cookie if excluding current session
    current_jti = None
    if exclude_current:
        token = request.cookies.get("access_token")
        if token:
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                current_jti = payload.get("jti")
            except JWTError:
                pass # If token is invalid, current_jti remains None

    query = db.query(SessionToken).filter(
        SessionToken.user_id == current_user.id,
        SessionToken.is_valid == True
    )

    if exclude_current and current_jti:
        query = query.filter(SessionToken.jti != current_jti)

    sessions_to_revoke = query.all()

    for session in sessions_to_revoke:
        session.is_valid = False
        session.revoked_at = datetime.utcnow()
    db.commit()
    logger.info(f"All eligible sessions revoked for user ID: {current_user.id}. Exclude current: {exclude_current}") # Add logging
    return {"message": "All eligible sessions revoked successfully"}

@app.post("/password-reset/request")
async def request_password_reset(
    reset_request: PasswordResetRequest,
    db: Session = Depends(get_db),
    request: Request = Request
):
    user = get_user(db, username=reset_request.username)
    if not user:
        # Always return a success message to prevent username enumeration
        logger.info(f"Password reset requested for a non-existent user.") # Redacted username
        return {"message": "If a matching account is found, a password reset link will be sent to your email."}

    # Invalidate any existing reset tokens for this user
    db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).update({"used_at": datetime.utcnow()})
    db.commit()

    token_id = str(uuid4())
    expires_at = datetime.utcnow() + timedelta(minutes=15) # 15-minute expiry

    # Create a signed token for the email link
    reset_jwt_payload = {"sub": user.username, "token_id": token_id, "type": "password_reset"}
    signed_token = jwt.encode(reset_jwt_payload, SECRET_KEY, algorithm=ALGORITHM)

    password_reset_token = PasswordResetToken(
        token_id=token_id,
        user_id=user.id,
        issued_at=datetime.utcnow(),
        expires_at=expires_at,
        ip_request=request.client.host
    )
    db.add(password_reset_token)
    db.commit()

    # Construct the reset link (frontend URL)
    # In a real application, this would be the frontend's password reset page
    # For now, we'll log it.
    reset_link = f"http://localhost:3000/reset-password?token={signed_token}"
    logger.info(f"Password reset link for user ID: {user.id} generated. Token ID: {token_id}") # Redacted username
    # TODO: Integrate with an email sending service here
    send_reset_email(to_email=user.username, reset_link=reset_link) # Assuming username is email for now


@app.post("/password-reset/reset")
async def reset_password(
    reset_confirm: PasswordResetConfirm,
    db: Session = Depends(get_db),
    request: Request = Request
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired password reset link."
    )
    try:
        payload = jwt.decode(reset_confirm.token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_id: str = payload.get("token_id")
        token_type: str = payload.get("type")

        if username is None or token_id is None or token_type != "password_reset":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user(db, username=username)
    if not user:
        raise credentials_exception

    reset_token_record = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_id == token_id,
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used_at == None, # Not yet used
        PasswordResetToken.expires_at > datetime.utcnow() # Not expired
    ).first()

    if not reset_token_record:
        raise credentials_exception

    # Update user's password
    user.hashed_password = get_password_hash(reset_confirm.new_password)
    reset_token_record.used_at = datetime.utcnow()
    reset_token_record.ip_use = request.client.host
    db.commit()

    # Invalidate all active sessions for the user after password reset
    db.query(SessionToken).filter(SessionToken.user_id == user.id).update(
        {"is_valid": False, "revoked_at": datetime.utcnow()}
    )
    db.commit()

    logger.info(f"Password successfully reset for user ID: {user.id}. All sessions revoked. Token ID: {token_id}") # Redact username, log user ID and token ID
    return {"message": "Password has been reset successfully. All your active sessions have been revoked."}
@app.post("/2fa/setup/generate")
async def generate_2fa_secret(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.totp_secret:
        raise HTTPException(status_code=400, detail="2FA is already set up.")
    
    secret = generate_totp_secret()
    current_user.totp_secret = secret
    db.commit()
    db.refresh(current_user)
    
    # For TOTP, the URI is used to generate the QR code on the frontend
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.username,
        issuer_name="PhantomNet"
    )
    logger.info(f"2FA secret generated for user ID: {current_user.id}") # Redact username
    return {"secret": secret, "otp_uri": otp_uri}

@app.post("/2fa/setup/verify")
async def verify_2fa_setup(code: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user.totp_secret:
        raise HTTPException(status_code=400, detail="2FA secret not generated yet.")
    
    if verify_totp_code(current_user.totp_secret, code):
        # 2FA is now enabled for the user
        current_user.webauthn_enabled = False # Ensure WebAuthn is false if TOTP is enabled
        current_user.trust_score = min(100, current_user.trust_score + 10)
        db.commit()
        db.refresh(current_user)
        logger.info(f"2FA successfully verified and enabled for user ID: {current_user.id}") # Redact username
        return {"message": "2FA successfully enabled."}
    else:
        logger.warning(f"Failed 2FA setup verification for user ID: {current_user.id}") # Redact username
        raise HTTPException(status_code=400, detail="Invalid 2FA code.")

@app.post("/2fa/disable")
async def disable_2fa(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user.totp_secret and not current_user.webauthn_enabled:
        raise HTTPException(status_code=400, detail="2FA is not enabled.")
    
    current_user.totp_secret = None
    current_user.webauthn_enabled = False
    current_user.twofa_enforced = False # If 2FA is disabled by user, it's not enforced for them
    current_user.trust_score = max(0, current_user.trust_score - 10)
    db.commit()
    db.refresh(current_user)
    logger.info(f"2FA disabled for user ID: {current_user.id}")
    return {"message": "2FA successfully disabled."}

@app.get("/2fa/recovery-codes", response_model=RecoveryCodeResponse, dependencies=[Depends(get_current_user)])
async def get_recovery_codes(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user.totp_secret and not current_user.webauthn_enabled:
        raise HTTPException(status_code=400, detail="2FA is not enabled for this user.")

    # Check for existing unused recovery codes
    existing_codes = db.query(RecoveryCode).filter(
        RecoveryCode.user_id == current_user.id,
        RecoveryCode.used_at == None
    ).all()

    if existing_codes:
        # Return existing codes (hashed, not plain)
        # For security, we should not return plain codes.
        # The UI should only allow downloading them once at generation.
        # For this API, we'll just confirm existence.
        return {"codes": ["****** (existing)"] * len(existing_codes)}
    else:
        # Generate new recovery codes
        codes = [generate_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
        hashed_codes = [hash_recovery_code(code) for code in codes]

        for hashed_code in hashed_codes:
            recovery_record = RecoveryCode(user_id=current_user.id, code_hash=hashed_code)
            db.add(recovery_record)
        db.commit()
        logger.info(f"Generated {RECOVERY_CODE_COUNT} recovery codes for user ID: {current_user.id}")
        return {"codes": codes} # Return plain codes only at generation time

@app.post("/2fa/recovery-codes/rotate", dependencies=[Depends(get_current_user)])
async def rotate_recovery_codes(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Invalidate all existing recovery codes for the user
    db.query(RecoveryCode).filter(RecoveryCode.user_id == current_user.id).update({"used_at": datetime.utcnow()})
    db.commit()

    # Generate new recovery codes
    codes = [generate_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
    hashed_codes = [hash_recovery_code(code) for code in codes]

    for hashed_code in hashed_codes:
        recovery_record = RecoveryCode(user_id=current_user.id, code_hash=hashed_code)
        db.add(recovery_record)
    db.commit()
    logger.info(f"Rotated recovery codes for user ID: {current_user.id}")
    return {"message": f"Rotated {RECOVERY_CODE_COUNT} recovery codes.", "codes": codes}

@app.post("/2fa/challenge", response_model=Token)
async def resolve_2fa_challenge(
    challenge_data: TwoFAChallenge,
    db: Session = Depends(get_db),
    request: Request = Request
):
    user_id_str = redis_client.get(f"2fa_challenge:{challenge_data.challenge_id}")
    if not user_id_str:
        raise HTTPException(status_code=400, detail="Invalid or expired 2FA challenge.")
    
    user_id = int(user_id_str.decode('utf-8'))
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found for challenge.")

    authenticated = False
    if challenge_data.code:
        if user.totp_secret and verify_totp_code(user.totp_secret, challenge_data.code):
            authenticated = True
    elif challenge_data.recovery_code:
        recovery_record = db.query(RecoveryCode).filter(
            RecoveryCode.user_id == user.id,
            RecoveryCode.used_at == None # Not yet used
        ).first()
        if recovery_record and verify_recovery_code(challenge_data.recovery_code, recovery_record.code_hash):
            recovery_record.used_at = datetime.utcnow()
            db.commit()
            authenticated = True
    
    if not authenticated:
        raise HTTPException(status_code=401, detail="Invalid 2FA code or recovery code.")

    # If 2FA challenge is successful, issue a new access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        db=db,
        user_id=user.id,
        data={"sub": user.username, "role": user.role, "user": user},
        expires_delta=access_token_expires,
        request=request
    )
    response = JSONResponse(content={"message": "2FA challenge successful, new token issued."})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="Lax",
        secure=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=access_token_expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
    )
    redis_client.delete(f"2fa_challenge:{challenge_data.challenge_id}") # Invalidate challenge
    logger.info(f"2FA challenge resolved for user ID: {user.id}")
    return response

class TrustMetrics(BaseModel):
    trust_score: float
    # Add other relevant metrics here if needed in the future

@app.get("/security/trust-metrics", response_model=TrustMetrics)
async def get_trust_metrics(current_user: User = Depends(get_current_user)):
    return {"trust_score": current_user.trust_score}

@app.get("/security/alerts", response_model=list[SecurityAlert])
async def get_security_alerts(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Fetch recent anomalies from AttackLog
    recent_anomalies = db.query(AttackLog).filter(
        AttackLog.is_anomaly == True
    ).order_by(AttackLog.timestamp.desc()).limit(10).all() # Get last 10 anomalies

    alerts = []
    for anomaly in recent_anomalies:
        alerts.append(SecurityAlert(
            timestamp=anomaly.timestamp.isoformat(),
            ip_address=anomaly.ip,
            risk_level="High", # Placeholder, could be derived from anomaly_score
            message=f"Anomaly detected: {anomaly.attack_type} from IP: {anomaly.ip} with score {anomaly.anomaly_score}"
        ))
    return alerts

@app.post("/security/alerts/webhooks", dependencies=[Depends(has_role([UserRole.ADMIN]))])
async def create_webhook(webhook: Webhook):
    raise HTTPException(status_code=501, detail="Not Implemented")

@app.get("/security/alerts/webhooks", dependencies=[Depends(has_role([UserRole.ADMIN]))])
async def get_webhooks():
    raise HTTPException(status_code=501, detail="Not Implemented")

@app.delete("/security/alerts/webhooks/{webhook_id}", dependencies=[Depends(has_role([UserRole.ADMIN]))])
async def delete_webhook(webhook_id: int):
    raise HTTPException(status_code=501, detail="Not Implemented")

# @app.post("/ai/anomaly-score")
# async def get_ai_anomaly_score(session_data: dict):
#     # For now, we'll just use the device fingerprint as the input to the model
#     data_to_predict = session_data.get("device_fingerprint", "")
#     prediction, confidence = brain.predict(data_to_predict)
#     return {"anomaly_score": confidence}

# @app.post("/ai/simulate-attack")
# async def simulate_ai_attack(simulation: AttackSimulation, db: Session = Depends(get_db)):
#     attack_type, confidence = brain.predict(simulation.data)

#     log_entry = AttackLog(
#         ip="127.0.0.1", # Simulated attack
#         port=0,
#         data=simulation.data,
#         attack_type=attack_type,
#         confidence_score=confidence,
#         is_anomaly=True, # All simulated attacks are considered anomalies
#         anomaly_score=confidence, # Use confidence as anomaly score
#     )
#     db.add(log_entry)
#     db.commit()

#     return {"attack_type": attack_type, "confidence": confidence}

# @app.post("/ai/simulate-attack")
# async def simulate_ai_attack(simulation: AttackSimulation, db: Session = Depends(get_db)):
#     attack_type, confidence = brain.predict(simulation.data)

#     log_entry = AttackLog(
#         ip="127.0.0.1", # Simulated attack
#         port=0,
#         data=simulation.data,
#         attack_type=attack_type,
#         confidence_score=confidence,
#         is_anomaly=True, # All simulated attacks are considered anomalies
#         anomaly_score=confidence, # Use confidence as anomaly score
#     )
#     db.add(log_entry)
#     db.commit()

#     return {"attack_type": attack_type, "confidence": confidence}



@app.get("/users/me/", response_model=UserInDB)
async def read_users_me(current_user: User = Depends(get_current_user)):
    logger.info(f"Accessed /users/me by user ID: {current_user.id}") # Redact username
    return current_user

@app.get("/health")
async def get_health_status():
    db_status = await check_database_health()
    overall_status = "Healthy" if db_status else "Degraded"
    return {"status": overall_status, "database": "Healthy" if db_status else "Degraded"}

async def broadcast_event(event_json: dict):
    for ws in list(clients):
        try:
            await ws.send_json(event_json)
        except RuntimeError:
            # This can happen if the WebSocket is already closed
            clients.remove(ws)
        except Exception as e:
            logger.error(f"Error broadcasting event: {e}") # Use logger
            clients.remove(ws)

# Placeholder for Smart Contract Interaction
async def write_merkle_root_to_contract(merkle_root: str, block_index: int):
    """
    Placeholder function to write the Merkle root to a Solidity smart contract on a testnet.
    For Cross-Chain Threat Ledger, this would be extended to:
    1.  Replicate the Merkle root to multiple ledgers (e.g., Ethereum, Hyperledger).
    2.  Potentially use Chainlink oracles to synchronize proofs across these ledgers.
    Full implementation would involve:
    1.  Configuring web3.py to connect to an Ethereum testnet (e.g., Sepolia, Goerli).
    2.  Compiling and deploying the Solidity contract (e.g., using Hardhat or Truffle).
    3.  Loading the contract ABI and address.
    4.  Calling the `logBatch` function of the deployed contract with the Merkle root.
    """
    logger.info(f"Simulating writing Merkle root {merkle_root} for block {block_index} to smart contract.") # Use logger
    # Example of how web3.py interaction would look (requires web3.py and contract setup):
    # from web3 import Web3
    # w3 = Web3(Web3.HTTPProvider("YOUR_TESTNET_RPC_URL"))
    # contract_address = "YOUR_CONTRACT_ADDRESS"
    # contract_abi = [...] # Your contract's ABI
    # contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    # tx_hash = contract.functions.logBatch(bytes.fromhex(merkle_root)).transact({'from': w3.eth.default_account})
    # receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    # print(f"Transaction receipt: {receipt}")

# Placeholder for IPFS Storage
async def store_on_ipfs(data: dict) -> str:
    """
    Placeholder function to simulate storing data on IPFS.
    Full implementation would involve:
    1.  Connecting to an IPFS node (e.g., using `ipfshttpclient` library).
    2.  Adding the data to IPFS.
    3.  Returning the CID (Content Identifier).
    """
    logger.info(f"Simulating storing data on IPFS: {data}") # Use logger
    # In a real scenario, this would return a CID
    return f"ipfs_cid_{hash(json.dumps(data, sort_keys=True))}"

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "phantomnet_agent", "config.json")

app.include_router(api_ecosystem_router, prefix="/api/v1/enterprise", tags=["Enterprise API"])

def get_blockchain(db: Session = Depends(get_db)):
    return Blockchain(db)

@app.post("/blockchain/add_transaction", dependencies=[Depends(has_role([UserRole.ADMIN]))])
async def add_blockchain_transaction(
    transaction: TransactionData,
    current_user: dict = Depends(get_current_user),
    blockchain: Blockchain = Depends(get_blockchain), # Inject the Blockchain dependency
    db: Session = Depends(get_db) # Inject the database session
):
    try:
        # Add a new transaction to the blockchain
        blockchain.new_transaction(
            sender="honeypot", # The agent is the sender
            recipient=transaction.ip,
            amount=1, # Placeholder, consider adding more meaningful data from transaction.data
        )

        # Mine a new block to record the transaction
        last_block_obj = blockchain.last_block
        last_proof = last_block_obj.proof if last_block_obj else 0 # Get proof from the last block object
        proof = blockchain.proof_of_work(last_proof)
        previous_hash = blockchain.hash(last_block_obj.to_dict()) if last_block_obj else '1' # Hash the last block object

        new_block_obj = blockchain.new_block(proof, previous_hash)
        db.add(new_block_obj) # Add the new block to the session
        db.commit() # Commit the new block to the database
        db.refresh(new_block_obj) # Refresh to get the ID and other generated fields

        # Broadcast the new block event
        await broadcast_event({"type": "new_block", "block": new_block_obj.to_dict()}) # Use to_dict() for broadcasting

        # Add event to Redis Stream
        redis_client.xadd('blockchain_events', {'type': 'new_block', 'block_index': new_block_obj.index, 'timestamp': new_block_obj.timestamp.isoformat()}) # Use isoformat for datetime

        # Call the placeholder for smart contract interaction
        if new_block_obj.merkle_root: # Only write if there are transactions and thus a Merkle root
            await write_merkle_root_to_contract(new_block_obj.merkle_root, new_block_obj.index)

        logger.info(f"Transaction added and block mined: {new_block_obj.index}") # Use logger
        return {"message": "Transaction added and block mined", "block_index": new_block_obj.index}
    except Exception as e:
        db.rollback() # Rollback changes in case of error
        logger.error(f"Error in add_blockchain_transaction: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred while processing the transaction."
        )

@app.post("/alerts/anomaly")
async def post_anomaly_alert(alert: AnomalyAlert):
    logger.info(f"Received anomaly alert: {alert.dict()}") # Use logger
    await broadcast_event({"type": "anomaly_alert", "alert": alert.dict()})
    return {"message": "Anomaly alert received and broadcasted"}

@app.post("/alerts/threat_verified")
async def post_threat_verified_alert(alert: ThreatVerifiedAlert):
    logger.info(f"Received verified threat alert: {alert.dict()}") # Use logger
    await broadcast_event({"type": "threat_verified_alert", "alert": alert.dict()})
    return {"message": "Verified threat alert received and broadcasted"}

@app.post("/alerts/blacklisted")
async def post_blacklisted_alert(alert: BlacklistedAlert):
    logger.info(f"Received blacklisted alert: {alert.dict()}") # Use logger
    await broadcast_event({"type": "blacklisted_alert", "alert": alert.dict()})
    return {"message": "Blacklisted alert received and broadcasted"}

# from backend_api.analyzer.model import get_qa_pipeline

def auto_select_persona(attack_event: AttackEvent) -> str:
    attack_type = attack_event.attack_type.lower()
    payload = attack_event.payload.lower()

    if "brute force" in attack_type or "scanning" in attack_type:
        return "analyst"
    elif "binary" in payload or "obfuscated" in payload:
        return "reverse_engineer"
    elif "intrusion" in attack_type or "exfil" in payload:
        return "prosecutor"
    else:
        return "analyst"  # Default persona

from phantomnet_agent.signatures.generator import generate_signatures, SignatureBundle

from phantomnet_agent.attribution.engine import attribute, AttributionResult
from phantomnet_agent.scoring.engine import compute_score, ThreatScore

from phantomnet_agent.scoring.engine import compute_score, ThreatScore

from phantomnet_agent.countermeasures.generator import generate_countermeasure, Countermeasure

@app.post("/chatbot", dependencies=[Depends(has_role([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER]))])
async def chatbot_query(query: ChatbotQuery, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    persona = query.persona if query.persona else auto_select_persona(query.attack_event)

    if persona == "analyst":
        response = f"Analyst response for attack type {query.attack_event.attack_type} from {query.attack_event.source_ip}"
    elif persona == "reverse_engineer":
        response = f"Reverse engineer response for attack type {query.attack_event.attack_type} from {query.attack_event.source_ip}"
    elif persona == "prosecutor":
        response = f"Prosecutor response for attack type {query.attack_event.attack_type} from {query.attack_event.source_ip}"
    else:
        response = "Invalid persona."

    signatures = generate_signatures(query.attack_event)
    attribution_result = attribute(query.attack_event)
    threat_score = compute_score(query.attack_event, attribution_result)
    countermeasure = generate_countermeasure(query.attack_event, attribution_result, threat_score)
    
    logger.info(f"Chatbot query processed for user ID: {current_user.id}. Query: {query.query}") # Review query.query for PII
    return {"response": response, "signatures": signatures.dict(), "attribution": attribution_result.dict(), "threat_score": threat_score.dict(), "countermeasure": countermeasure.dict(), "redteam_run_id": query.attack_event.redteam_run_id}

from phantomnet_agent.digital_twin import generator, deployer, models
import yaml
from phantomnet_agent.red_teaming.api import router as red_teaming_router

app.include_router(red_teaming_router, prefix="/api", tags=["Red Teaming"])

@app.post("/digital_twin/render", response_model=models.TwinInstance)
async def render_digital_twin(template_id: str, params: dict, current_user: dict = Depends(get_current_user)):
    try:
        with open(f"C:/Users/VILAS/downloads/PhantomNet-v2.0/PhantomNet-v2.0/phantomnet_agent/digital_twin/presets/{template_id}.yaml", "r") as f:
            template_data = yaml.safe_load(f)
        template = models.TwinTemplate(**template_data)
        instance = generator.render_template(template, params)
        logger.info(f"Digital twin rendered for user ID: {current_user.id}. Instance ID: {instance.instance_id}") # Redact username
        return instance
    except FileNotFoundError:
        logger.warning(f"Digital twin template not found: {template_id}") # No PII
        raise HTTPException(status_code=404, detail="Template not found")
    except Exception as e:
        logger.error(f"Error rendering digital twin: {e}", exc_info=True) # No PII
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/digital_twin/deploy")
async def deploy_digital_twin(instance: models.TwinInstance, current_user: dict = Depends(get_current_user)):
    try:
        workdir = deployer.deploy_instance(instance)
        logger.info(f"Digital twin deployed for user ID: {current_user.id}. Instance ID: {instance.instance_id} in {workdir}") # Redact username
        return {"message": f"Instance {instance.instance_id} deployed successfully in {workdir}"}
    except Exception as e:
        logger.error(f"Error deploying digital twin: {e}", exc_info=True) # No PII
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/honeypot/control", dependencies=[Depends(has_role([UserRole.ADMIN]))])
async def honeypot_control(control: HoneypotControl, current_user: dict = Depends(get_current_user)):
    if control.action == "start":
        logger.info(f"User ID: {current_user.id} simulating starting honeypot on port {control.port}") # Redact username
        return {"message": f"Honeypot simulated to start on port {control.port}"}
    elif control.action == "stop":
        logger.info(f"User ID: {current_user.id} simulating stopping honeypot on port {control.port}") # Redact username
        return {"message": f"Honeypot simulated to stop on port {control.port}"}
    else:
        logger.warning(f"User ID: {current_user.id} attempted invalid honeypot action: {control.action}") # Redact username
        raise HTTPException(status_code=400, detail="Invalid action. Must be 'start' or 'stop'.")

@app.post("/honeypot/simulate_attack", dependencies=[Depends(has_role([UserRole.ADMIN, UserRole.ANALYST]))])
async def simulate_attack(attack: SimulateAttack, current_user: dict = Depends(get_current_user)):
    logger.info(f"User ID: {current_user.id} simulating attack from IP: {attack.ip} on port {attack.port} with data: [REDACTED]") # Redact username and attack.data
    # In a real scenario, this would send data to the collector service
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://collector:8001/logs/ingest", # Directly call the collector service
                json={
                    "ip": attack.ip,
                    "port": attack.port,
                    "data": attack.data
                }
            )
            response.raise_for_status()
            logger.info(f"Simulated attack data sent to collector by user ID: {current_user.id}") # Redact username
            return {"message": "Simulated attack data sent to collector", "collector_response": response.json()}
    except httpx.RequestError as e:
        logger.error(f"User ID: {current_user.id} failed to send simulated attack to collector: {e}", exc_info=True) # Redact username
        raise HTTPException(status_code=500, detail=f"Failed to send simulated attack to collector: {e}")

@app.get("/")
def home():
    logger.info("Root endpoint accessed.") # Use logger
    return {"message": "PhantomNet API Running"}

@app.get("/logs", dependencies=[Depends(has_role([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER]))])
def get_logs(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    logs = db.query(AttackLog).order_by(AttackLog.timestamp.desc()).all()
    # Convert AttackLog objects to dictionaries or a suitable format for the frontend
    logger.info(f"User ID: {current_user.id} fetched logs.") # Redact username
    return {"logs": [{"timestamp": log.timestamp.isoformat(), "ip": log.ip, "port": log.port, "data": log.data, "attack_type": log.attack_type, "confidence_score": log.confidence_score, "is_anomaly": log.is_anomaly, "anomaly_score": log.anomaly_score, "is_verified_threat": log.is_verified_threat, "is_blacklisted": log.is_blacklisted} for log in logs]}

@app.get("/config", dependencies=[Depends(has_role([UserRole.ADMIN]))])
def get_config(current_user: dict = Depends(get_current_user)):
    # Note: Exposing the agent's configuration, even if not critically sensitive,
    # can provide reconnaissance information to an authenticated attacker.
    # Consider implementing more granular access control or filtering sensitive fields
    # if this endpoint is exposed to non-administrative users in production.
    if not os.path.exists(CONFIG_FILE):
        logger.warning(f"User ID: {current_user.id} attempted to fetch non-existent config file.") # Redact username
        return {"error": "Config file not found"}, 404
    with open(CONFIG_FILE) as f:
        config = json.load(f)
    logger.info(f"User ID: {current_user.id} fetched config.") # Redact username
    return config

@app.get("/blockchain", dependencies=[Depends(has_role([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER]))])
def get_blockchain_data(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    blocks = db.query(Block).order_by(Block.index).all()
    logger.info(f"User ID: {current_user.id} fetched blockchain data.") # Redact username
    return [block.to_dict() for block in blocks]

@app.post("/blockchain/verify", dependencies=[Depends(has_role([UserRole.ADMIN]))])
async def verify_blockchain_integrity(db: Session = Depends(get_db)):
    blockchain_instance = Blockchain(db)
    is_valid = blockchain_instance.is_chain_valid()
    if is_valid:
        logger.info("Blockchain integrity verified: All blocks are valid.") # Use logger
        return {"message": "Blockchain integrity verified: All blocks are valid."}
    else:
        logger.warning("Blockchain integrity compromised: Tampering detected.") # Use logger
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Blockchain integrity compromised: Tampering detected.")

@app.get("/ip-info/{ip_address}", dependencies=[Depends(has_role([UserRole.ADMIN, UserRole.ANALYST]))])
async def get_ip_info(ip_address: str, current_user: dict = Depends(get_current_user)):
    async with httpx.AsyncClient() as client:
        response = await client.get(f"http://ip-api.com/json/{ip_address}")
        if response.status_code == 200:
            logger.info(f"User ID: {current_user.id} fetched IP info for IP: {ip_address}.") # Redact username
            return response.json()
        else:
            logger.error(f"User ID: {current_user.id} failed to fetch IP info for IP: {ip_address}: Status {response.status_code}") # Redact username
            return {"error": "Failed to fetch IP info"}, response.status_code

@app.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.add(websocket)
    logger.info("Client connected to /ws/events.") # No PII
    try:
        while True:
            # Keep the connection alive. Incoming messages are not expected for this broadcast endpoint.
            await websocket.receive_text()
    except WebSocketDisconnect:
        clients.remove(websocket)
        logger.info("Client disconnected from events.") # No PII
    except Exception as e:
        clients.remove(websocket)
        logger.error(f"WebSocket event error: {e}", exc_info=True) # No PII
        import traceback
        traceback.print_exc()

@app.websocket("/ws/logs")
async def websocket_log_endpoint(
    websocket: WebSocket,
    token: str = None,
    db: Session = Depends(get_db) # Inject the database session
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # Assuming we can get user ID from username here, or pass it through the token
    user = get_user(db, username=username) # Fetch user to get ID
    user_id_for_logging = user.id if user else "UNKNOWN"

    await websocket.accept()
    clients.add(websocket) # Add to the general clients set for broadcasting
    logger.info(f"Client connected to /ws/logs. User ID: {user_id_for_logging}") # Redact username
    try:
        # Send existing logs from the database
        logs = db.query(AttackLog).order_by(AttackLog.timestamp.desc()).limit(100).all() # Limit to 100 for initial load
        formatted_logs = [{"timestamp": log.timestamp.isoformat(), "ip": log.ip, "port": log.port, "data": log.data, "attack_type": log.attack_type, "confidence_score": log.confidence_score, "is_anomaly": log.is_anomaly, "anomaly_score": log.anomaly_score, "is_verified_threat": log.is_verified_threat, "is_blacklisted": log.is_blacklisted} for log in logs]
        await websocket.send_json({"type": "initial_logs", "logs": formatted_logs})

        # Keep the connection alive. New logs will be broadcasted via broadcast_event
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        clients.remove(websocket)
        logger.info(f"Client disconnected from /ws/logs. User ID: {user_id_for_logging}") # Redact username
    except Exception as e:
        clients.remove(websocket)
        import traceback
        logger.error(f"WebSocket log error: {e}", exc_info=True) # No PII
        traceback.print_exc()
    finally:
        await websocket.close()