from typing import Optional
from .models import Playbook, RedTeamRun, RedTeamRunStatus
from .playbook_library import load_playbook
from datetime import datetime
import uuid

class Orchestrator:
    def __init__(self):
        self.runs: Dict[str, RedTeamRun] = {}

    def validate_playbook_safety(self, playbook: Playbook, mode: str) -> bool:
        if playbook.safety.destructive and mode != "sandboxed_malware":
            # Destructive playbooks should only run in sandboxed_malware mode with explicit consent
            return False
        if playbook.safety.sandbox_required and mode != "sandboxed_malware":
            return False
        # Add more safety checks here (e.g., regex for real credentials)
        return True

    def schedule_run(self, playbook_id: str, instance_id: str, mode: str, operator_id: str) -> RedTeamRun:
        playbook = load_playbook(playbook_id)
        if not self.validate_playbook_safety(playbook, mode):
            raise ValueError("Playbook failed safety validation.")

        run_id = f"rtr-{uuid.uuid4().hex[:8]}"
        status = RedTeamRunStatus(status="queued", start_time=datetime.now())
        run = RedTeamRun(
            id=run_id,
            playbook_id=playbook_id,
            instance_id=instance_id,
            mode=mode,
            operator_id=operator_id,
            status=status
        )
        self.runs[run_id] = run
        return run

    def get_run_status(self, run_id: str) -> RedTeamRun:
        if run_id not in self.runs:
            raise ValueError(f"Run {run_id} not found.")
        return self.runs[run_id]

    def update_run_status(self, run_id: str, status: str, message: Optional[str] = None):
        if run_id not in self.runs:
            raise ValueError(f"Run {run_id} not found.")
        self.runs[run_id].status.status = status
        self.runs[run_id].status.message = message
        if status == "completed" or status == "failed":
            self.runs[run_id].status.end_time = datetime.now()
