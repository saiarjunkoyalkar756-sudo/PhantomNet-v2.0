from pydantic import BaseModel
from phantomnet_agent.attribution.engine import AttributionResult
from phantomnet_agent.scoring.engine import ThreatScore

class AttackEvent(BaseModel):
    log_id: int
    attack_type: str
    source_ip: str
    payload: str
    twin_instance_id: str | None = None

class Countermeasure(BaseModel):
    action: str
    reason: str
    urgency: str   # low / medium / high

def generate_countermeasure(
    event: AttackEvent,
    attribution: AttributionResult,
    score: ThreatScore
) -> Countermeasure:
    if score.score < 20:
        return Countermeasure(
            action="monitor only",
            reason="Low threat score indicates harmless noise.",
            urgency="low"
        )
    if attribution.cluster == "Ransomware prep actor":
        return Countermeasure(
            action="block source IP + enforce MFA on admin endpoints",
            reason="Attribution suggests ransomware preparation.",
            urgency="high"
        )
    if attribution.cluster == "APT-like actor":
        return Countermeasure(
            action="segment network & restrict lateral movement",
            reason="Attribution suggests a sophisticated APT-style actor.",
            urgency="high"
        )
    if attribution.cluster == "Semi-skilled web exploitation crew":
        return Countermeasure(
            action="apply WAF rule for specific signature",
            reason="Attribution suggests a web exploitation attempt.",
            urgency="medium"
        )
    if attribution.cluster == "Opportunistic criminal botnet":
        return Countermeasure(
            action="rate limit high-freq brute source",
            reason="Attribution suggests an automated botnet.",
            urgency="medium"
        )

    return Countermeasure(
        action="monitor only",
        reason="No specific countermeasure for this threat.",
        urgency="low"
    )
