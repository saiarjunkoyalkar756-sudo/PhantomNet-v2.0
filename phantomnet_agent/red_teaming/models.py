from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from datetime import datetime

class Target(BaseModel):
    service: str
    port: Optional[int] = None
    endpoint: Optional[str] = None

class Parameters(BaseModel):
    username_list: Optional[List[str]] = None
    password_list: Optional[List[str]] = None
    max_attempts_per_min: Optional[int] = None
    payload: Optional[str] = None

class Safety(BaseModel):
    destructive: bool = False
    sandbox_required: bool = False
    allow_payloads: bool = False

class Playbook(BaseModel):
    id: str
    description: str
    type: str
    target: Target
    parameters: Parameters
    safety: Safety

class RedTeamRunStatus(BaseModel):
    status: str  # e.g., queued, running, completed, failed
    message: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

class RedTeamRun(BaseModel):
    id: str
    playbook_id: str
    instance_id: str
    mode: str  # emulation or sandboxed_malware
    operator_id: str
    status: RedTeamRunStatus
    metrics: Dict = {}
    report_url: Optional[str] = None

class RedTeamReport(BaseModel):
    run_id: str
    status: str
    timeline: List[Dict] = []
    metrics: Dict = {}
    signatures: List[Dict] = []
    recommendations: List[str] = []
    pdf_report_data: Optional[str] = None  # Base64 encoded PDF
