import enum
from dataclasses import dataclass
from datetime import datetime

class Tier(enum.Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"

@dataclass
class License:
    tier: Tier
    expires_at: datetime | None

def check_feature_allowed(license: License, feature: str) -> bool:
    if feature == "campaign graph builder":
        return license.tier in [Tier.PRO, Tier.ENTERPRISE]
    if feature == "attribution engine":
        return license.tier in [Tier.PRO, Tier.ENTERPRISE]
    if feature == "auto countermeasure":
        return license.tier == Tier.ENTERPRISE
    if feature == "multiple digital twins":
        return license.tier in [Tier.PRO, Tier.ENTERPRISE]
    if feature == "unlimited digital twins":
        return license.tier == Tier.ENTERPRISE
    return True
