from sqlalchemy.orm import Session
from backend_api.database import SessionLocal, User, SessionToken, AttackLog, Agent
import random
from backend_api.message_bus import publish_message
from sqlalchemy import text

def get_random_agent(db: Session):
    agents = db.query(Agent).all()
    if agents:
        return random.choice(agents)
    return None
from loguru import logger
import asyncio
import httpx
from datetime import datetime, timedelta

async def check_database_health():
    try:
        db = SessionLocal()
        # Try to execute a simple query to check connection
        db.execute(text("SELECT 1"))
        db.close()
        logger.info("Database health check: OK", status="healthy")
        # Metrics: Increment database_health_status_ok_total
        return True
    except Exception as e:
        logger.error("Database health check: FAILED", status="unhealthy", error=str(e))
        # Metrics: Increment database_health_status_failed_total
        return False

async def check_api_gateway_health():
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("http://localhost:8000/")
            if response.status_code == 200:
                logger.info("API Gateway health check: OK", status="healthy")
                # Metrics: Increment api_gateway_health_status_ok_total
                return True
            else:
                logger.error("API Gateway health check: FAILED", status="unhealthy", status_code=response.status_code)
                # Metrics: Increment api_gateway_health_status_failed_total
                return False
    except Exception as e:
        logger.error("API Gateway health check: FAILED", status="unhealthy", error=str(e))
        # Metrics: Increment api_gateway_health_status_failed_total
        return False

async def check_other_services_health():
    # Placeholder for checking other microservices
    logger.info("Other services health check: OK (placeholder)", status="healthy")
    # Metrics: Increment other_services_health_status_ok_total
    return True

async def check_jwt_expiry_anomalies():
    try:
        db = SessionLocal()
        stale_session_threshold = datetime.utcnow() - timedelta(hours=24)
        stale_sessions = db.query(SessionToken).filter(
            SessionToken.is_valid == True,
            SessionToken.created_at < stale_session_threshold
        ).all()

        for session in stale_sessions:
            logger.warning("Stale session detected", user_id=session.user_id, session_created_at=session.created_at)
            
            # Log anomaly
            anomaly = AttackLog(
                ip=session.ip,
                port=0, # N/A for this type of anomaly
                data=f"Stale session detected for user ID: {session.user_id}",
                attack_type="jwt_expiry_anomaly",
                confidence_score=0.8,
                is_anomaly=True,
                anomaly_score=0.8,
            )
            db.add(anomaly)

            # Adjust trust score
            user = db.query(User).filter(User.id == session.user_id).first()
            if user:
                user.trust_score = max(0, user.trust_score - 5)

        # Check for mass token expiry
        one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
        expired_token_count = db.query(SessionToken).filter(
            SessionToken.expires_at < datetime.utcnow(),
            SessionToken.expires_at > one_minute_ago
        ).count()

        if expired_token_count > 100:
            logger.warning("Mass token expiry detected", expired_token_count=expired_token_count)
            # Metrics: Increment jwt_mass_expiry_total
            # Audit: Record jwt.verify_failed event (reason: mass_expiry)
            # In a real scenario, you might want to take further action here, like notifying an admin.

        db.commit()
        db.close()
    except Exception as e:
        logger.error("Error checking for JWT expiry anomalies", error=str(e))
        # Metrics: Increment jwt_expiry_anomaly_check_failed_total

async def check_certificate_validity():
    # Placeholder for checking certificate validity (e.g., expiry, revocation status)
    # In a real scenario, this would involve checking against a CRL or OCSP endpoint.
    logger.info("Certificate validity check: OK (placeholder)")
    # Metrics: Increment certificate_validity_check_success_total
    return True

async def gossip_protocol():
    try:
        db = SessionLocal()
        agents = db.query(Agent).all()
        if not agents:
            db.close()
            logger.info("Gossip protocol skipped: No agents found")
            # Metrics: Increment gossip_protocol_skipped_total
            return

        # For simplicity, each agent will gossip its own trust score to a random peer.
        # In a real scenario, agents would exchange partial trust maps.
        for agent in agents:
            # Create a trust map for the current agent (for now, just its own trust score)
            trust_map = {agent.id: 1.0} # Placeholder for actual trust score

            # Select a random peer to send the gossip to
            peer = get_random_agent(db)
            if peer and peer.id != agent.id:
                try:
                    async with httpx.AsyncClient() as client:
                        response = await client.post(
                            f"http://localhost:8000/api/agents/{peer.id}/gossip",
                            json={"trust_map": trust_map}
                        )
                        response.raise_for_status()
                        logger.info("Agent gossiped successfully", agent_id=agent.id, peer_id=peer.id)
                        # Metrics: Increment gossip_message_sent_total
                except httpx.RequestError as e:
                    logger.error("Error gossiping between agents", agent_id=agent.id, peer_id=peer.id, error=str(e))
                    # Metrics: Increment gossip_message_send_failed_total

        db.close()
    except Exception as e:
        logger.error("Error in gossip protocol", error=str(e))
        # Metrics: Increment gossip_protocol_error_total

async def check_key_rotation():
    try:
        db = SessionLocal()
        agents = db.query(Agent).all()
        for agent in agents:
            # For simplicity, we'll check if the key was created more than 90 days ago.
            # In a real scenario, you would check the AgentCredential.created_at.
            if agent.last_seen and (datetime.utcnow() - agent.last_seen) > timedelta(days=90):
                logger.info("Agent key due for rotation", agent_id=agent.id)
                # Metrics: Increment agent_key_rotation_due_total
                try:
                    async with httpx.AsyncClient() as client:
                        response = await client.post(f"http://localhost:8000/api/agents/{agent.id}/rotate-key")
                        response.raise_for_status()
                        logger.info("Agent key rotation triggered successfully", agent_id=agent.id)
                        # Metrics: Increment agent_key_rotation_triggered_total
                        # Audit: Record cert.rotated event (triggered by health_monitor)
                except httpx.RequestError as e:
                    logger.error("Error triggering agent key rotation", agent_id=agent.id, error=str(e))
                    # Metrics: Increment agent_key_rotation_trigger_failed_total
        db.close()
    except Exception as e:
        logger.error("Error in key rotation check", error=str(e))
        # Metrics: Increment key_rotation_check_error_total

async def monitor_health(interval: int = 60):
    while True:
        db_healthy = await check_database_health()
        api_gateway_healthy = await check_api_gateway_health()
        other_services_healthy = await check_other_services_health()
        await check_jwt_expiry_anomalies()
        await check_certificate_validity()
        await gossip_protocol()
        await check_key_rotation()

        if not db_healthy:
            logger.warning("Database is unhealthy. Simulating restart...")
            # In a real scenario, you would have logic to restart the database or notify an admin.

        if not api_gateway_healthy:
            logger.warning("API Gateway is unhealthy. Simulating restart...")
            # In a real scenario, you would have logic to restart the API gateway.

        if not other_services_healthy:
            logger.warning("One or more other services are unhealthy. Simulating restart...")
            # In a real scenario, you would have logic to restart the unhealthy services.

        await asyncio.sleep(interval)
