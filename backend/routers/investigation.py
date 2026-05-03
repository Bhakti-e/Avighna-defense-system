"""
Investigation Console Router
Provides controlled command execution for security investigation
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import subprocess
import re
import platform

router = APIRouter()


class CommandRequest(BaseModel):
    command: str


# Whitelist of allowed commands
ALLOWED_COMMANDS = ["ping", "tracert", "traceroute", "nslookup", "nmap", "arp", "netstat"]

# Command patterns to block dangerous flags
DANGEROUS_PATTERNS = [
    r"rm\s+-rf",
    r"del\s+/",
    r"format",
    r"mkfs",
    r"dd\s+if=",
    r">\s*/dev/",
    r"curl.*\|.*sh",
    r"wget.*\|.*sh",
]


def is_command_safe(command: str) -> tuple[bool, str]:
    """
    Check if command is safe to execute
    Returns (is_safe, error_message)
    """
    cmd_parts = command.strip().split()
    if not cmd_parts:
        return False, "Empty command"
    
    cmd_name = cmd_parts[0].lower()
    
    # Check if command is in whitelist
    if cmd_name not in ALLOWED_COMMANDS:
        return False, f"Command '{cmd_name}' is not allowed. Allowed: {', '.join(ALLOWED_COMMANDS)}"
    
    # Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return False, "Command contains dangerous pattern"
    
    return True, ""


def execute_command(command: str) -> str:
    """
    Execute command safely with timeout
    """
    try:
        # Adjust command for Windows vs Unix
        if platform.system() == "Windows":
            # Replace traceroute with tracert on Windows
            command = command.replace("traceroute", "tracert")
        
        # Execute with timeout
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,  # 30 second timeout
            encoding='utf-8',
            errors='replace'
        )
        
        output = result.stdout
        if result.stderr:
            output += f"\n{result.stderr}"
        
        if not output.strip():
            output = "Command completed with no output"
        
        return output
    
    except subprocess.TimeoutExpired:
        return "ERROR: Command timed out after 30 seconds"
    except Exception as e:
        return f"ERROR: Command execution failed: {str(e)}"


@router.post("/execute")
def execute_investigation_command(request: CommandRequest):
    """
    Execute a whitelisted investigation command
    """
    command = request.command.strip()
    
    # Validate command safety
    is_safe, error_msg = is_command_safe(command)
    if not is_safe:
        raise HTTPException(status_code=400, detail=error_msg)
    
    # Execute command
    output = execute_command(command)
    
    return {
        "command": command,
        "output": output,
        "success": not output.startswith("ERROR")
    }


@router.get("/allowed-commands")
def get_allowed_commands():
    """
    Get list of allowed investigation commands
    """
    return {
        "commands": ALLOWED_COMMANDS,
        "description": "Whitelisted security investigation commands"
    }
