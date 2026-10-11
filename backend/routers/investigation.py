"""Remote diagnostics are disabled for the MVP. No command execution code."""
from fastapi import APIRouter, Depends, HTTPException
from ..auth import require_admin

router = APIRouter(dependencies=[Depends(require_admin)])

@router.post("/execute")
def execute_investigation_command():
    raise HTTPException(503, "Diagnostic console is disabled. No command was executed.")

@router.get("/allowed-commands")
def get_allowed_commands():
    return {"commands": [], "enabled": False}
