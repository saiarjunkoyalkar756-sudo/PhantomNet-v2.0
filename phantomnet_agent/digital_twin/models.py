from pydantic import BaseModel, Field
from typing import List, Dict, Optional

class ServiceConfig(BaseModel):
    name: str
    image: Optional[str] = None
    ports: List[str] = []
    env: Dict[str, str] = {}
    files: Dict[str, str] = {}  # path -> content
    fake_endpoints: List[str] = []

class TwinTemplate(BaseModel):
    template_id: str
    description: Optional[str] = None
    category: str  # e.g., "bank", "cloud", "iot"
    services: List[ServiceConfig]
    metadata: Dict[str, str] = {}
    deception_level: int = Field(1, ge=1, le=5)  # 1=light, 5=deep

class TwinInstance(BaseModel):
    instance_id: str
    template_id: str
    created_at: str
    params: Dict[str, str]  # user-specified parameters (domain, org name, fake creds)
    docker_compose_yaml: Optional[str] = None
    kubernetes_yaml: Optional[str] = None
