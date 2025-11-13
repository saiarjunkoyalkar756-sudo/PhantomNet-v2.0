from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from datetime import datetime
import asyncio
from loguru import logger
import json

from backend_api.database import get_db, Agent, AgentCredential, append_to_event_log
from backend_api.schemas import AgentRegistration, AgentHeartbeat, GossipMessage, BootstrapToken, SecurityEvent
from backend_api.security_utils import generate_key_pair, sign_certificate, create_inter_node_jwt, verify_inter_node_jwt, sign_data, verify_signature
from backend_api.message_bus import subscribe_to_channel, publish_message
from features.cognitive_core_intelligence.cognitive_core import CognitiveCore
from features.synthetic_cognitive_memory.cognitive_memory import CognitiveMemory
from backend_api.database import SessionLocal

router = APIRouter()

# Create a CognitiveMemory instance with a new DB session
cognitive_memory_instance = CognitiveMemory(db_session=SessionLocal())
cognitive_core_instance = CognitiveCore(cognitive_memory=cognitive_memory_instance)

import secrets
import time

# ... (existing imports)

# In-memory store for bootstrap tokens. In a real-world scenario, use Redis or a database.
# Store as a dictionary: {token: expiration_timestamp}
bootstrap_tokens = {}

@router.post("/agents/bootstrap-token")
async def create_bootstrap_token(db: Session = Depends(get_db)):
    """
    Generates a single-use, time-expired bootstrap token for agent registration.
    """
    token = secrets.token_hex(32)
    # Token expires in 5 minutes
    expiration = time.time() + 300
    bootstrap_tokens[token] = expiration
    logger.info(f"Generated bootstrap token: {token}")
    return {"bootstrap_token": token, "expires_in": 300}

import hashlib
from cryptography import x509

# ... (existing code)

@router.post("/agents/register")
async def register_agent(agent_data: AgentRegistration, db: Session = Depends(get_db)):
    # ... (bootstrap token validation)

    # Generate key pair and store public key
    private_key_pem, public_key_pem = generate_key_pair()

    # Sign the agent's public key with our CA
    signed_cert_pem = sign_certificate(
        public_key_pem=public_key_pem,
        ca_private_key_pem=ca_key.decode('utf-8'),
        ca_certificate_pem=ca_cert.decode('utf-8'),
        common_name=f"agent-{agent_data.public_key[:10]}"
    )
    
    # Load the signed certificate to extract information
    signed_cert = x509.load_pem_x509_certificate(signed_cert_pem.encode('utf-8'))

    # Generate public key fingerprint
    public_key_bytes = signed_cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = hashlib.sha256(public_key_bytes).hexdigest()

    new_agent = Agent(
        public_key=public_key_pem,
        public_key_fingerprint=fingerprint,
        cert_serial=str(signed_cert.serial_number),
        role=agent_data.role,
        version=agent_data.version,
        location=agent_data.location,
        status="online",
        last_seen=datetime.utcnow(),
        quarantined=True # New agents are quarantined by default
    )
    db.add(new_agent)
    db.commit()
    db.refresh(new_agent)

    agent_credential = AgentCredential(
        agent_id=new_agent.id,
        public_key_pem=public_key_pem
    )
    db.add(agent_credential)
    db.commit()
    db.refresh(agent_credential)

    logger.info("Agent registered successfully", agent_id=new_agent.id, role=new_agent.role, location=new_agent.location)
    # Return the signed certificate to the agent
    return {"agent": new_agent, "certificate": signed_cert_pem}

from backend_api.crl_utils import is_certificate_revoked, revoke_certificate

# ... (existing code)

@router.post("/agents/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: int, heartbeat: AgentHeartbeat, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        logger.warning("Agent heartbeat failed: Agent not found", agent_id=agent_id)
        raise HTTPException(status_code=404, detail="Agent not found")

    # CRL Check
    if is_certificate_revoked(db, agent.cert_serial):
        logger.warning("Agent heartbeat denied: Certificate has been revoked", agent_id=agent_id, cert_serial=agent.cert_serial)
        raise HTTPException(status_code=403, detail="Certificate has been revoked")

    agent.status = heartbeat.status
    agent.last_seen = datetime.utcnow()
    db.commit()

    # ... (rest of the function)

@router.post("/agents/{agent_id}/revoke-certificate")
async def revoke_agent_certificate(agent_id: int, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    revoke_certificate(db, agent.cert_serial, reason="Manual revocation by administrator")
    logger.info(f"Certificate for agent {agent_id} has been revoked.")
    return {"message": "Certificate revoked successfully."}

@router.get("/agents")
async def get_agents(db: Session = Depends(get_db)):
    agents = db.query(Agent).all()
    return agents

@router.post("/agents/{agent_id}/gossip")
async def agent_gossip(agent_id: int, gossip: GossipMessage, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        logger.warning("Agent gossip failed: Agent not found", agent_id=agent_id)
        raise HTTPException(status_code=404, detail="Agent not found")

    # In a real implementation, you would implement a gossip protocol to propagate and average trust scores.
    # For now, we'll just log the received trust map.
        logger.info("Received gossip from agent", agent_id=agent_id, trust_map=gossip.trust_map)
        # Metrics: Increment agent_gossip_received_total
        return {"message": "Gossip received"}

@router.post("/agents/{agent_id}/rotate-key")
async def rotate_agent_key(agent_id: int, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        logger.warning("Agent key rotation failed: Agent not found", agent_id=agent_id)
        raise HTTPException(status_code=404, detail="Agent not found")

    # Generate new key pair
    private_key_pem, public_key_pem = generate_key_pair()

    # Mark old credential as rotated
    old_credential = db.query(AgentCredential).filter(AgentCredential.agent_id == agent_id, AgentCredential.revoked_at == None).first()
    if old_credential:
        old_credential.rotated_at = datetime.utcnow()
        db.add(old_credential)

    # Create new credential
    new_credential = AgentCredential(
        agent_id=agent.id,
        public_key_pem=public_key_pem,
        created_at=datetime.utcnow()
    )
    db.add(new_credential)

    # Simulate certificate signing for the new public key
    dummy_ca_private_key = "-----BEGIN PRIVATE KEY-----\n...DUMMY_CA_PRIVATE_KEY...\n-----END PRIVATE KEY-----"
    dummy_ca_certificate = "-----BEGIN CERTIFICATE-----\n...DUMMY_CA_CERTIFICATE...\n-----END CERTIFICATE-----"
    
    signed_cert = sign_certificate(
        public_key_pem=public_key_pem,
        ca_private_key_pem=dummy_ca_private_key,
        ca_certificate_pem=dummy_ca_certificate,
        common_name=f"agent-{agent.public_key[:10]}-rotated" # New common name for rotated key
    )
    agent.public_key = public_key_pem # Update agent's public key
    agent.public_key_fingerprint = "DUMMY_FINGERPRINT_ROTATED" # Placeholder
    agent.cert_serial = "DUMMY_CERT_SERIAL_ROTATED" # Placeholder
    db.add(agent)

    db.commit()
    db.refresh(agent)
    db.refresh(new_credential)

    logger.info("Agent key rotated successfully", agent_id=agent.id)
    # Metrics: Increment agent_key_rotation_success_total
    # Audit: Record cert.rotated event
    return {"message": "Key rotated successfully"}

@router.post("/agents/{agent_id}/approve")
async def approve_agent(agent_id: int, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        logger.warning("Agent approval failed: Agent not found", agent_id=agent_id)
        raise HTTPException(status_code=404, detail="Agent not found")

    agent.quarantined = False
    db.add(agent)
    db.commit()
    db.refresh(agent)

    logger.info("Agent approved successfully", agent_id=agent.id)
    # Audit: Record agent.approved event
    return {"message": "Agent approved successfully"}

@router.post("/analyze-threat")
async def analyze_threat_endpoint(threat_data: dict):
    """
    Endpoint to analyze threat data using the Cognitive Core.
    Expects a JSON body with a "threat_string" key.
    """
    threat_string = threat_data.get("threat_string")
    if not threat_string:
        raise HTTPException(status_code=400, detail="'threat_string' not provided in request body")
    
    analysis_result = cognitive_core_instance.analyze_threat(threat_string)
    return analysis_result

@router.websocket("/ws/agent-events")
async def websocket_agent_events(websocket: WebSocket):
    await websocket.accept()
    pubsub = subscribe_to_channel("agent-events")

    try:
        while True:
            message = pubsub.get_message()
            if message and message['type'] == 'message':
                data = json.loads(message['data'])
                jwt_token = data.get("jwt")
                event_data = data.get("data")

                if jwt_token:
                    try:
                        # In a real scenario, you would retrieve the public key of the sending agent
                        # from the database based on the 'iss' claim in the JWT.
                        # For now, we'll use a dummy public key for verification.
                        dummy_public_key = "-----BEGIN PUBLIC KEY-----\n...DUMMY_PUBLIC_KEY...\n-----END PUBLIC KEY-----"
                        
                        verified_payload = verify_inter_node_jwt(jwt_token, dummy_public_key, "default_cluster")
                        logger.info("JWT verified successfully", payload=verified_payload)
                        # Metrics: Increment jwt_verification_success_total

                        # Verify agent's signature on event data
                        agent_signature = event_data.get("agent_signature")
                        heartbeat_data = {"agent_id": event_data.get("agent_id"), "status": event_data.get("status")}
                        heartbeat_data_bytes = json.dumps(heartbeat_data).encode('utf-8')

                        if agent_signature and verify_signature(heartbeat_data_bytes, agent_signature, dummy_public_key):
                            logger.info("Agent signature verified successfully")
                            # Attest the event (sign with receiving node's private key)
                            # For now, use a dummy private key for attestation
                            dummy_private_key = "-----BEGIN PRIVATE KEY-----\n...DUMMY_PRIVATE_KEY...\n-----END PRIVATE KEY-----"
                            node_attestation = sign_data(heartbeat_data_bytes, dummy_private_key)
                            event_data["node_attestation"] = node_attestation
                            event_data["receiving_node_id"] = 1 # Dummy node ID
                            await websocket.send_text(json.dumps(event_data))
                        else:
                            logger.warning("Agent signature verification failed or missing", agent_id=event_data.get("agent_id"))

                    except HTTPException as e:
                        logger.error("JWT verification failed", error=e.detail)
                        # Metrics: Increment jwt_verification_failure_total (by reason)
                        # Audit: Record jwt.verify_failed event
                    except Exception as e:
                        logger.error("Error during JWT verification", error=str(e))
                        # Metrics: Increment jwt_verification_failure_total (by reason)
                        # Audit: Record jwt.verify_failed event
                else:
                    logger.warning("Message received without JWT", data=event_data)
                    await websocket.send_text(json.dumps(event_data))
            await asyncio.sleep(0.1) # Prevent busy-waiting
    except WebSocketDisconnect:
        pubsub.close()

