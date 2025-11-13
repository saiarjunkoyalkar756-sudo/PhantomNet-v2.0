import os
import yaml
from typing import List, Dict
from .models import Playbook

PLAYBOOK_DIR = os.path.join(os.path.dirname(__file__), "playbooks")
os.makedirs(PLAYBOOK_DIR, exist_ok=True)

def load_playbook(playbook_id: str) -> Playbook:
    filepath = os.path.join(PLAYBOOK_DIR, f"{playbook_id}.yaml")
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Playbook {playbook_id} not found")
    with open(filepath, "r") as f:
        data = yaml.safe_load(f)
    return Playbook(**data)

def save_playbook(playbook: Playbook):
    filepath = os.path.join(PLAYBOOK_DIR, f"{playbook.id}.yaml")
    with open(filepath, "w") as f:
        yaml.dump(playbook.dict(), f)

def list_playbooks() -> List[str]:
    playbooks = []
    for filename in os.listdir(PLAYBOOK_DIR):
        if filename.endswith(".yaml"):
            playbooks.append(os.path.splitext(filename)[0])
    return playbooks
