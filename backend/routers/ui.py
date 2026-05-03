# backend/routers/ui.py
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from pathlib import Path

router = APIRouter()

@router.get("/ui", response_class=HTMLResponse)
def dashboard():
    path = Path("templates/dashboard.html")
    if not path.exists():
        return HTMLResponse("<h3>dashboard.html missing in /templates</h3>")
    
    # Add cache-busting headers to force browser reload
    content = path.read_text(encoding="utf-8")
    
    return HTMLResponse(
        content=content,
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )

# Backwards-compatible route: allow /dashboard as an alias for /ui
@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_alias():
    return dashboard()

@router.get("/phone-agent", response_class=HTMLResponse)
def phone_agent():
    """Web-based phone agent for easy testing"""
    path = Path("web_phone_agent.html")
    if not path.exists():
        return HTMLResponse("<h3>web_phone_agent.html missing</h3>")
    
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    
    return HTMLResponse(
        content=content,
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )
