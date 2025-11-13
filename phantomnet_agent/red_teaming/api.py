from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from .models import Playbook, RedTeamRun, RedTeamReport
from .playbook_library import load_playbook, save_playbook, list_playbooks
from .orchestrator import Orchestrator
from .executor import Executor
from .reporter import Reporter
from backend_api.auth import get_current_user, UserRole, has_role

router = APIRouter()
orchestrator = Orchestrator()
executor = Executor()
reporter = Reporter()

@router.post("/redteam/run", response_model=RedTeamRun)
async def start_redteam_run(
    playbook_id: str,
    instance_id: str,
    mode: str = "emulation",
    operator_id: str = Depends(get_current_user),
):
    try:
        run = orchestrator.schedule_run(playbook_id, instance_id, mode, operator_id["username"])
        # In a real scenario, this would be a background task
        # asyncio.create_task(executor.execute_playbook_emulation(run, load_playbook(playbook_id)))
        return run
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/redteam/run/{run_id}", response_model=RedTeamRun)
async def get_redteam_run_status(run_id: str, current_user: dict = Depends(get_current_user)):
    try:
        return orchestrator.get_run_status(run_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.get("/redteam/run/{run_id}/report", response_model=RedTeamReport)
async def get_redteam_run_report(run_id: str, current_user: dict = Depends(get_current_user)):
    # Placeholder for fetching actual events related to the run
    mock_events = [] # In a real scenario, fetch from DB
    run = orchestrator.get_run_status(run_id)
    return reporter.generate_report(run, mock_events)

@router.get("/redteam/playbooks", response_model=List[str])
async def get_playbooks(current_user: dict = Depends(get_current_user)):
    return list_playbooks()

@router.post("/redteam/playbook", dependencies=[Depends(has_role([UserRole.ADMIN]))])
async def add_playbook(playbook: Playbook, current_user: dict = Depends(get_current_user)):
    try:
        save_playbook(playbook)
        return {"message": f"Playbook {playbook.id} added successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))