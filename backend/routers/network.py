"""
Network Monitoring API Router
==============================
Endpoints for network device discovery and management
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Dict, Any
from ..database import get_db
from ..scanning.passive_scanner import network_scanner
from ..scanning.scapy_monitor import scapy_monitor
from ..config import settings
import logging
import time

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/live")
def get_live_devices():
    """
    Get network monitoring statistics from Scapy
    NOTE: Device list comes from unified device manager, not Scapy
    This endpoint only shows Scapy monitoring stats
    """
    if not settings.enable_scapy_monitor:
        return {
            "enabled": False,
            "message": "Scapy monitoring disabled in config",
            "stats": {}
        }
    
    stats = scapy_monitor.get_stats()
    alerts = scapy_monitor.get_alerts()
    
    return {
        "enabled": True,
        "stats": stats,
        "alerts": alerts,
        "timestamp": time.time(),
        "note": "For device list, use /devices/ endpoint"
    }


@router.get("/alerts")
def get_network_alerts():
    """
    Get real-time network attack alerts from Scapy
    Includes: ARP spoofing, MAC spoofing, probe floods
    """
    if not settings.enable_scapy_monitor:
        return {
            "enabled": False,
            "alerts": []
        }
    
    alerts = scapy_monitor.get_alerts()
    
    return {
        "enabled": True,
        "count": len(alerts),
        "alerts": alerts
    }


@router.get("/stats")
def get_monitoring_stats():
    """Get Scapy monitoring statistics"""
    if not settings.enable_scapy_monitor:
        return {
            "enabled": False,
            "stats": {}
        }
    
    stats = scapy_monitor.get_stats()
    
    return {
        "enabled": True,
        "stats": stats
    }


class DeviceAuthorization(BaseModel):
    mac_address: str
    authorized: bool = True


class DeviceBlock(BaseModel):
    mac_address: str
    reason: str = "Manual block"


@router.get("/devices")
def get_network_devices():
    """
    Get all discovered network devices
    
    Returns:
    - List of devices with IP, MAC, vendor, authorization status
    """
    try:
        devices = network_scanner.get_all_devices()
        return {
            "status": "success",
            "count": len(devices),
            "devices": devices
        }
    except Exception as e:
        logger.error(f"Failed to get devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/devices/rogue")
def get_rogue_devices():
    """
    Get list of unauthorized (rogue) devices detected on network
    
    Returns:
    - List of rogue devices that are not in whitelist
    """
    try:
        rogue = network_scanner.get_rogue_devices()
        return {
            "status": "success",
            "count": len(rogue),
            "rogue_devices": rogue,
            "warning": "These devices are not authorized and may pose a security risk"
        }
    except Exception as e:
        logger.error(f"Failed to get rogue devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan/stats")
def get_scan_stats():
    """
    Get network scanner statistics
    
    Returns:
    - Scan count, device counts, last scan time
    """
    try:
        stats = network_scanner.get_stats()
        return {
            "status": "success",
            "stats": stats
        }
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/now")
def trigger_scan():
    """
    Trigger immediate network scan (instead of waiting for scheduled scan)
    
    Returns:
    - Scan results with discovered devices
    """
    try:
        logger.info("Manual network scan triggered")
        network_scanner._perform_scan()
        
        devices = network_scanner.get_all_devices()
        rogue = network_scanner.get_rogue_devices()
        
        return {
            "status": "success",
            "message": "Network scan completed",
            "total_devices": len(devices),
            "rogue_devices": len(rogue),
            "devices": devices
        }
    except Exception as e:
        logger.error(f"Manual scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/devices/authorize")
def authorize_device(auth: DeviceAuthorization):
    """
    Authorize a device (add to whitelist)
    
    Body:
    - mac_address: Device MAC address
    - authorized: true to authorize, false to unauthorize
    """
    try:
        mac = auth.mac_address.upper().replace('-', ':')
        
        if auth.authorized:
            network_scanner.authorize_device(mac)
            message = f"Device {mac} authorized"
        else:
            network_scanner.unauthorize_device(mac)
            message = f"Device {mac} unauthorized"
        
        return {
            "status": "success",
            "message": message,
            "mac_address": mac,
            "authorized": auth.authorized
        }
    except Exception as e:
        logger.error(f"Authorization failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/devices/block")
def block_device(block: DeviceBlock):
    """
    Block a device (add to blacklist)
    
    Body:
    - mac_address: Device MAC address
    - reason: Reason for blocking
    """
    try:
        mac = block.mac_address.upper().replace('-', ':')
        
        network_scanner.block_device(mac, block.reason)
        
        # TODO: Trigger actual network blocking (router + gateway)
        
        return {
            "status": "success",
            "message": f"Device {mac} blocked",
            "mac_address": mac,
            "reason": block.reason
        }
    except Exception as e:
        logger.error(f"Block failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/devices/unblock")
def unblock_device(mac_address: str):
    """
    Unblock a device (remove from blacklist)
    
    Query param:
    - mac_address: Device MAC address
    """
    try:
        mac = mac_address.upper().replace('-', ':')
        
        network_scanner.unblock_device(mac)
        
        # TODO: Remove network blocking (router + gateway)
        
        return {
            "status": "success",
            "message": f"Device {mac} unblocked",
            "mac_address": mac
        }
    except Exception as e:
        logger.error(f"Unblock failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config")
def get_network_config():
    """
    Get current network monitoring configuration
    """
    return {
        "status": "success",
        "config": {
            "network_monitoring_enabled": settings.network_monitoring_enabled,
            "network_cidr": settings.network_cidr,
            "network_scan_interval": settings.network_scan_interval,
            "auto_block_rogue_devices": settings.auto_block_rogue_devices,
            "scanner_running": network_scanner.running
        }
    }
