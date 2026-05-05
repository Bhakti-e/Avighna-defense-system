# backend/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import actions, ui, simulate, discovery
from .routers import telemetry_db as telemetry
from .routers import alerts_db as alerts
from .routers import devices_db as devices
from .routers import reports_db as reports_db
from .routers import reports
from .background_tasks import start_background_tasks
from . import state
from .database import init_db

# 1️⃣ Create the FastAPI app FIRST
import logging
import os
import signal
import threading
import traceback

# Configure file logging for debugging startup/shutdown issues
LOG_PATH = os.environ.get('DOME_LOG', 'backend.log')
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
                    handlers=[logging.FileHandler(LOG_PATH, encoding='utf-8'), logging.StreamHandler()])
logger = logging.getLogger('dome')

app = FastAPI(
    title="AVIGHNA Defense Edition",
    description="Network Defense & Threat Detection Platform v3.0",
    version="3.0.0"
)

# Add CORS middleware to allow frontend access
# Get allowed origins from environment variable or use defaults
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
allowed_origins = [
    "http://localhost:3000",
    "http://localhost:3001",  # Added for when 3000 is in use
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",  # Added for when 3000 is in use
    FRONTEND_URL,
]

# Add wildcard for Vercel preview deployments
if "vercel.app" in FRONTEND_URL:
    allowed_origins.append("https://*.vercel.app")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database on startup
@app.on_event("startup")
def startup_event():
    from .database import check_db_connection
    
    logger.info("Initializing database...")
    
    # Check database connection
    if not check_db_connection():
        logger.error("Database connection failed! Check DATABASE_URL configuration")
    
    init_db()
    logger.info("Database initialized successfully")
    
    # Log database type
    db_url = os.environ.get("DATABASE_URL", "sqlite:///./avighna_defense.db")
    if db_url.startswith("postgresql"):
        logger.info("Using PostgreSQL database")
    else:
        logger.info("Using SQLite database (development mode)")

# Register signal handlers to dump stack traces when process receives signals
def _dump_threads_stack(signum, frame):
    try:
        logger.warning(f"Received signal {signum}: dumping thread stacks...")
        for thread_id, frame in sys._current_frames().items():
            logger.warning(f"--- Thread {thread_id} ---")
            logger.warning(''.join(traceback.format_stack(frame)))
    except Exception as e:
        logger.exception('Failed to dump thread stacks: %s', e)
    finally:
        # After dumping stacks, exit the process so Ctrl+C / SIGINT behaves as expected
        try:
            logger.info('Exiting process after signal %s', signum)
        except Exception:
            pass
        # Use os._exit to ensure immediate termination from signal handler context
        os._exit(1)

import sys
signal.signal(signal.SIGINT, _dump_threads_stack)
# SIGTERM may not be available on Windows, but register if possible
try:
    signal.signal(signal.SIGTERM, _dump_threads_stack)
except Exception:
    pass

# 2️⃣ Simple health/root endpoints
from fastapi.responses import HTMLResponse
from pathlib import Path

@app.get("/")
def root():
    """API root endpoint"""
    return {
        "name": "AVIGHNA Defense Edition",
        "version": "3.0.0",
        "edition": "defense",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "telemetry": "/telemetry",
            "alerts": "/alerts",
            "devices": "/devices",
            "network": "/network",
            "reconnaissance": "/reconnaissance"
        }
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

# 3️⃣ Register all routers AFTER app is created
# authentication
from .routers import auth
app.include_router(auth.router, prefix="/auth", tags=["authentication"])
# telemetry and monitoring
app.include_router(telemetry.router, prefix="/telemetry", tags=["telemetry"])
app.include_router(alerts.router,     prefix="/alerts",    tags=["alerts"])
app.include_router(actions.router,    prefix="/actions",   tags=["actions"])
app.include_router(reports.router,    prefix="/reports",   tags=["reports"])
app.include_router(reports_db.router, prefix="/reports-db", tags=["reports-db"])
# devices router exposes list at /devices/  (you can also include without prefix if you want)
app.include_router(devices.router,    prefix="/devices",   tags=["devices"])
# manual device registration
from .routers import manual_devices
app.include_router(manual_devices.router, prefix="/manual-devices", tags=["manual-devices"])
# reconnaissance monitoring
from .routers import reconnaissance_monitoring
app.include_router(reconnaissance_monitoring.router, prefix="/reconnaissance", tags=["reconnaissance"])
# device discovery
from .routers import discovery
app.include_router(discovery.router, prefix="/discovery", tags=["discovery"])
# network monitoring
from .routers import network
app.include_router(network.router, prefix="/network", tags=["network"])
# statistics aggregation
from .routers import stats
app.include_router(stats.router, prefix="/stats", tags=["stats"])
# investigation console
from .routers import investigation
app.include_router(investigation.router, prefix="/investigation", tags=["investigation"])
# ui router serves dashboard at /dashboard (no prefix)
app.include_router(ui.router,                         tags=["ui"])
app.include_router(simulate.router, prefix="/simulate", tags=["simulate"]) 

# 4️⃣ Start background tasks on app startup (recommended)
@app.on_event("startup")
def _startup():
    # Log basic startup info
    try:
        logger.info(f"Starting DOME backend (PID: {os.getpid()})")
        logger.debug(f"Current user: {os.getlogin() if hasattr(os, 'getlogin') else 'unknown'}")
    except Exception:
        logger.exception('Could not log startup environment')

    # run discovery / scanning worker as a background thread
    try:
        start_background_tasks()
        logger.info('Background tasks started')
    except Exception as e:
        logger.exception('[!] start_background_tasks failed: %s', e)

    # Record current threads
    try:
        threads = threading.enumerate()
        logger.debug('Threads at startup: %s', [t.name for t in threads])
    except Exception:
        logger.exception('Failed to list threads')

    # Start network scanner (if enabled)
    try:
        from .config import settings
        from .scanning import network_scanner
        
        if settings.network_monitoring_enabled:
            network_scanner.network_cidr = settings.network_cidr
            network_scanner.scan_interval = settings.network_scan_interval
            network_scanner.start()
            logger.info(f'Network scanner started - monitoring {settings.network_cidr}')
        else:
            logger.info('Network monitoring disabled in config')
    except Exception as e:
        logger.exception('[!] network scanner startup failed: %s', e)


@app.on_event('shutdown')
def _shutdown():
    try:
        logger.info('DOME backend shutting down (shutdown event)')
        threads = threading.enumerate()
        logger.debug('Threads at shutdown: %s', [t.name for t in threads])
    except Exception:
        logger.exception('Error during shutdown logging')
