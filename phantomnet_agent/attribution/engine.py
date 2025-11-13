from pydantic import BaseModel
import re

class AttackEvent(BaseModel):
    log_id: int
    attack_type: str
    source_ip: str
    payload: str

class AttributionResult(BaseModel):
    cluster: str
    confidence: float
    reasoning: str

def attribute(event: AttackEvent) -> AttributionResult:
    payload = event.payload.lower()
    attack_type = event.attack_type.lower()

    # APT style precision actor
    if (
        ("SELECT" in event.payload and "FROM" in event.payload and "WHERE" in event.payload)
        and (len(event.payload) > 100)
    ):
        return AttributionResult(
            cluster="APT style precision actor",
            confidence=0.8,
            reasoning="Targeted and complex SQL query detected, suggesting a sophisticated actor."
        )

    # Ransomware prep actor
    if "powershell" in payload or "base64" in payload:
        return AttributionResult(
            cluster="Ransomware prep actor",
            confidence=0.7,
            reasoning="Use of PowerShell or base64 encoding is common in ransomware preparation."
        )

    # Semi-skilled web exploitation crew
    if "sql" in attack_type:
        return AttributionResult(
            cluster="Semi-skilled web exploitation crew",
            confidence=0.6,
            reasoning="SQL injection attempt detected, typical of web exploitation crews."
        )

    # Opportunistic criminal botnet
    if "brute force" in attack_type or "scanning" in attack_type:
        return AttributionResult(
            cluster="Opportunistic criminal botnet",
            confidence=0.5,
            reasoning="High volume of connection attempts suggests an automated botnet."
        )

    return AttributionResult(
        cluster="Unknown",
        confidence=0.1,
        reasoning="Could not attribute the attack based on the available data."
    )
