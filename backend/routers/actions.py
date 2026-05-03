# backend/routers/actions.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from .. import state
import time
import uuid
import os
import logging
from ..utils.quarantine import block_ip, unblock_ip, disconnect_wifi

router = APIRouter()
logger = logging.getLogger('dome.actions')

class QuarantineReq(BaseModel):
    device_id: str
    reason: str = "Manual isolation"

@router.post("/quarantine")
def quarantine(req: QuarantineReq):
    """
    Auto-isolate a device:
    1. Mark as quarantined
    2. Block IP at firewall level
    3. Simulate WiFi disconnect (for demo)
    4. Create isolation alert
    """
    dev = state.devices.setdefault(req.device_id, {"quarantined": False, "last_seen": 0.0})
    dev["quarantined"] = True
    dev["last_seen"] = time.time()
    dev["status"] = "ISOLATED"
    dev["quarantine_time"] = time.time()
    dev["quarantine_reason"] = req.reason
    
    # perform network-level block if we have IP
    ip = dev.get("ip")
    mac = dev.get("mac", req.device_id)
    
    quarantine_actions = {
        "firewall_blocked": False,
        "wifi_disconnected": False,
        "ip": ip,
        "mac": mac,
    }
    
    if ip:
        try:
            block_result = block_ip(ip)
            quarantine_actions["firewall_blocked"] = True
            print(f"[QUARANTINE] IP {ip} blocked: {block_result}")
        except Exception as e:
            print(f"[ERROR] Failed to block IP {ip}: {e}")
    
    # Simulate WiFi disconnect for demo
    try:
        wifi_result = disconnect_wifi(mac)
        quarantine_actions["wifi_disconnected"] = True
        print(f"[QUARANTINE] WiFi disconnect for {mac}: {wifi_result}")
    except Exception as e:
        print(f"[ERROR] Failed to disconnect WiFi: {e}")
    
    # Create quarantine alert
    isolation_alert = {
        "id": str(uuid.uuid4()),
        "device_id": req.device_id,
        "reason": f"AUTO-ISOLATION: {req.reason}",
        "severity": 4,  # Critical
        "action": "quarantine",
        "quarantine_actions": quarantine_actions,
        "ts": time.time(),
    }
    state.alerts.insert(0, isolation_alert)
    
    return {
        "status": "quarantined",
        "device_id": req.device_id,
        "actions": quarantine_actions,
        "alert_id": isolation_alert["id"]
    }

@router.post("/unquarantine")
def unquarantine(req: QuarantineReq):
    dev = state.devices.setdefault(req.device_id, {"quarantined": False, "last_seen": 0.0})
    dev["quarantined"] = False
    dev["last_seen"] = time.time()
    return {"status": "unquarantined", "device_id": req.device_id}


class ObservationReq(BaseModel):
    device_id: str
    reason: str = "Automatic observation"
    limit_kbps: int = 100
    allowed_outbound: list = []

@router.post("/observe")
def observe(req: ObservationReq):
    """Place device under observation: limit bandwidth, restrict outbound and add observation metadata."""
    dev = state.devices.setdefault(req.device_id, {"quarantined": False, "last_seen": 0.0})
    dev["status"] = "UNDER_OBSERVATION"
    dev["observation"] = {
        "start": time.time(),
        "reason": req.reason,
        "limit_kbps": req.limit_kbps,
        "allowed_outbound": req.allowed_outbound
    }

    # apply observation actions (simulated)
    try:
        from ..utils.observation import apply_observation
        actions = apply_observation(req.device_id, ip=dev.get("ip"), params={"limit_kbps": req.limit_kbps, "allowed_ips": req.allowed_outbound})
        dev["observation_actions"] = actions
    except Exception as e:
        print(f"[ERROR] Failed to apply observation: {e}")

    observation_alert = {
        "id": str(uuid.uuid4()),
        "device_id": req.device_id,
        "reason": f"OBSERVATION: {req.reason}",
        "severity": 2,
        "action": "observe",
        "ts": time.time(),
    }
    state.alerts.insert(0, observation_alert)

    return {"status": "observed", "device_id": req.device_id, "actions": dev.get("observation_actions")}


@router.post("/unobserve")
def unobserve(req: ObservationReq):
    dev = state.devices.setdefault(req.device_id, {"quarantined": False, "last_seen": 0.0})
    dev["status"] = "OK"
    dev.pop("observation", None)
    dev.pop("observation_actions", None)
    return {"status": "unobserved", "device_id": req.device_id}


@router.get("/device/{device_id}")
def device_status(device_id: str):
    dev = state.devices.get(device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="device not found")
    return {"device_id": device_id, **dev}


@router.post('/shutdown')
def shutdown_server():
    """Emergency shutdown endpoint for local demos: force the process to exit.

    NOTE: This will immediately terminate the backend process. Intended for local/demo use only.
    """
    try:
        logger.warning('Shutdown endpoint called: exiting process')
    except Exception:
        pass
    # Use os._exit to ensure immediate termination
    os._exit(0)
