from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import datetime
import time
import hashlib
import json

DATABASE_URL = "sqlite:///./backend_api/test.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models required by the existing API Gateway
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String)
    twofa_enforced = Column(Boolean, default=False)
    totp_secret = Column(String, nullable=True)
    webauthn_enabled = Column(Boolean, default=False)
    trust_score = Column(Float, default=100.0)

class SessionToken(Base):
    __tablename__ = "session_tokens"
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime)
    is_valid = Column(Boolean, default=True)
    revoked_at = Column(DateTime, nullable=True)
    ip = Column(String)
    user_agent = Column(String)

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token_id = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    issued_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime)
    used_at = Column(DateTime, nullable=True)
    ip_request = Column(String)
    ip_use = Column(String, nullable=True)

class AttackLog(Base):
    __tablename__ = "attack_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    ip = Column(String)
    port = Column(Integer)
    data = Column(String)
    attack_type = Column(String)
    confidence_score = Column(Float)
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float)
    is_verified_threat = Column(Boolean, default=False)
    is_blacklisted = Column(Boolean, default=False)

class BlacklistedIP(Base):
    __tablename__ = "blacklisted_ips"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    reason = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class RecoveryCode(Base):
    __tablename__ = "recovery_codes"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    code_hash = Column(String, nullable=False)
    used_at = Column(DateTime, nullable=True)

class Block(Base):
    __tablename__ = "blocks"
    id = Column(Integer, primary_key=True, index=True)
    index = Column(Integer, unique=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    data = Column(String, nullable=False)
    previous_hash = Column(String, nullable=False)
    hash = Column(String, unique=True, nullable=False)
    proof = Column(Integer, nullable=False)
    merkle_root = Column(String, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "index": self.index,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
            "proof": self.proof,
            "merkle_root": self.merkle_root
        }

class Agent(Base):
    __tablename__ = "agents"
    id = Column(Integer, primary_key=True, index=True)
    public_key = Column(String, unique=True, nullable=False)
    public_key_fingerprint = Column(String, nullable=False)
    cert_serial = Column(String, nullable=False)
    role = Column(String, nullable=False)
    version = Column(String, nullable=False)
    location = Column(String, nullable=False)
    status = Column(String, nullable=False)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    quarantined = Column(Boolean, default=True)

class AgentCredential(Base):
    __tablename__ = "agent_credentials"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"))
    public_key_pem = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    rotated_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)

class RevokedCertificate(Base):
    __tablename__ = "revoked_certificates"
    id = Column(Integer, primary_key=True, index=True)
    serial_number = Column(String, unique=True, index=True, nullable=False)
    revocation_date = Column(DateTime, default=datetime.datetime.utcnow)
    reason = Column(String)

# My new tables
class CognitiveMemoryDB(Base):
    __tablename__ = "cognitive_memory"
    id = Column(Integer, primary_key=True, index=True)
    threat_data = Column(String, unique=True, nullable=False)
    episode_data = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class PhantomChainDB(Base):
    __tablename__ = "phantom_chain"
    block_index = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, nullable=False)
    data = Column(String, nullable=False)
    previous_hash = Column(String, nullable=False)
    hash = Column(String, unique=True, nullable=False)


def create_db_and_tables():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# This function is kept for compatibility but now uses SQLAlchemy
def initialize_database():
    create_db_and_tables()
    print("Database initialized successfully using SQLAlchemy.")

def get_db_connection():
    """ This function is now a bit of a misnomer, but we'll keep it for compatibility
        with the refactored classes. It returns a SQLAlchemy session. """
    return SessionLocal()

def append_to_event_log(event_type: str, details: dict):
    """Placeholder for appending events to an audit log."""
    print(f"Event Log: Type={event_type}, Details={details}")

if __name__ == '__main__':
    initialize_database()