# backend/state.py - CLEAN RESET
from typing import List, Dict, Any
import time
from .config import settings

# EMPTY STATE - NO FAKE DATA
alerts: List[Dict[str, Any]] = []           # existing alerts (newest first)

# Device history for reconnaissance detection
device_history: Dict[str, List] = {}  # device_id -> list of (timestamp, event_type, data) tuples

# Reconnaissance detection data (for proactive scanning)
reconnaissance_data: Dict[str, Dict[str, Any]] = {}  # EMPTY - no fake recon data
reconnaissance_findings: List[Dict[str, Any]] = []   # EMPTY - no fake findings

# NOTE: Device storage moved to unified device_manager.py
# All device operations now go through device_manager

# FORCE PRINT TO CONFIRM CLEAN STATE
print("🔥 STATE MODULE RESET - ALL DATA CLEARED")
print(f"🚨 Alerts: {len(alerts)}")
print(f"🔍 Reconnaissance: {len(reconnaissance_findings)}")
print("📊 Devices: Managed by device_manager.py")
