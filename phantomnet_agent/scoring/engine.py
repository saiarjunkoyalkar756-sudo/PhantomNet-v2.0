from pydantic import BaseModel
from phantomnet_agent.attribution.engine import AttributionResult

class AttackEvent(BaseModel):
    log_id: int
    attack_type: str
    source_ip: str
    payload: str

class ThreatScore(BaseModel):
    score: int
    factors: list[str]
    reasoning: str

def compute_score(event: AttackEvent, attribution: AttributionResult) -> ThreatScore:
    score = 0
    factors = []
    reasoning = ""

    if "binary" in event.payload.lower() or "upload" in event.payload.lower():
        score += 25
        factors.append("Payload contains binary or file upload")

    if "base64" in event.payload.lower() or "powershell" in event.payload.lower():
        score += 15
        factors.append("Payload contains base64 or powershell")

    if attribution.cluster == "Ransomware prep actor":
        score += 20
        factors.append("Attribution cluster is ransomware prep actor")

    if attribution.cluster == "APT-like actor":
        score += 30
        factors.append("Attribution cluster is APT-like actor")

    if len(event.payload) > 4:
        score += 10
        factors.append("Payload has more than 4 substrings")

    # Placeholder for high-risk ASN check
    # if is_high_risk_asn(event.source_ip):
    #     score += 5
    #     factors.append("Attacker from high-risk ASN")

    score = min(score, 100)

    if score >= 80:
        reasoning = "Extremely dangerous adversary"
    elif score >= 60:
        reasoning = "Dangerous adversary"
    elif score >= 40:
        reasoning = "Moderate threat"
    elif score >= 20:
        reasoning = "Low threat"
    else:
        reasoning = "Harmless noise"

    return ThreatScore(score=score, factors=factors, reasoning=reasoning)
