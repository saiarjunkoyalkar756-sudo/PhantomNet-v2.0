from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    role: Optional[str] = "user"

class UserInDB(UserBase):
    id: int
    hashed_password: str
    role: str

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None
    twofa_enabled: bool = False
    twofa_enforced: bool = False

class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None
    recovery_code: Optional[str] = None # Add recovery_code to login request
    device_fingerprint: Optional[str] = None # Add device_fingerprint

class PasswordResetRequest(BaseModel):
    username: str

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

class RecoveryCodeResponse(BaseModel):
    codes: list[str]

class TwoFACode(BaseModel):
    code: str

class TwoFAChallenge(BaseModel):
    challenge_id: str
    code: Optional[str] = None
    recovery_code: Optional[str] = None

class MFARequiredResponse(BaseModel):
    mfa_required: bool = True
    challenge_id: str

class SecurityAlert(BaseModel):
    timestamp: str
    ip_address: str
    risk_level: str
    message: str
    # Add other relevant fields like user_id, session_id, etc., as needed

class Webhook(BaseModel):
    url: str
    events: list[str]

class AttackSimulation(BaseModel):
    data: str

class AgentRegistration(BaseModel):
    public_key: str
    role: str
    version: str
    location: str
    bootstrap_token: Optional[str] = None

class BootstrapToken(BaseModel):
    token: str

class AgentKeyPair(BaseModel):
    private_key: str
    public_key: str

class SecurityEvent(BaseModel):
    event_data: dict
    originating_agent_id: int
    agent_signature: str
    receiving_node_id: Optional[int] = None
    node_attestation: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_event_hash: Optional[str] = None
    event_hash: Optional[str] = None

class AgentHeartbeat(BaseModel):
    status: str
    metrics: dict
    trust_delta: float

class GossipMessage(BaseModel):
    trust_map: dict[int, float]
