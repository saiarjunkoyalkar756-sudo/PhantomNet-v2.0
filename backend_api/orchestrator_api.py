from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import os
from sqlalchemy.orm import Session
from backend_api.database import get_db

# This is a bit of a hack for now to make sure the orchestrator has a file to snapshot
# In a real system, this would be a path to a critical system file
DUMMY_SYSTEM_FILE = "dummy_system_state.txt"
if not os.path.exists(DUMMY_SYSTEM_FILE):
    with open(DUMMY_SYSTEM_FILE, "w") as f:
        f.write("Initial system state.")

from phantomnet_agent.orchestrator import Orchestrator

router = APIRouter()

def get_orchestrator(db: Session = Depends(get_db)) -> Orchestrator:
    return Orchestrator(db_session=db, target_system_file=DUMMY_SYSTEM_FILE)

class ThreatData(BaseModel):
    threat_string: str

class MarketplaceModule(BaseModel):
    developer_id: str
    module_name: str
    module_code: str

@router.post("/orchestrator/threats/")
async def handle_threat_endpoint(threat_data: ThreatData, orchestrator: Orchestrator = Depends(get_orchestrator)):
    """
    Receives a threat, passes it to the orchestrator, and returns the analysis.
    """
    analysis = orchestrator.cognitive_core.analyze_threat(threat_data.threat_string)
    if analysis.get("threat_level") == "critical":
        orchestrator.handle_threat(threat_data.threat_string)
        return {"message": "Critical threat detected and handled.", "analysis": analysis}
    return {"message": "Threat analyzed.", "analysis": analysis}

@router.post("/orchestrator/marketplace/validate")
async def validate_module_endpoint(module_data: MarketplaceModule, orchestrator: Orchestrator = Depends(get_orchestrator)):
    """
    Receives a new marketplace module and passes it to the orchestrator for validation.
    """
    orchestrator.validate_marketplace_module(
        developer_id=module_data.developer_id,
        module_name=module_data.module_name,
        module_code=module_data.module_code
    )
    return {"message": "Module submitted for validation. Check the blockchain for confirmation."}

@router.get("/orchestrator/blockchain/")
async def get_blockchain_endpoint(orchestrator: Orchestrator = Depends(get_orchestrator)):
    """
    Returns the current state of the PhantomChain.
    """
    return {"chain": orchestrator.phantom_chain.chain}
