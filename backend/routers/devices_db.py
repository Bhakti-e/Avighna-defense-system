# backend/routers/devices_db.py
"""
Devices router with DATABASE integration
"""
from fastapi import APIRouter, Query, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from ..db_utils import get_all_devices, compute_telemetry_health

router = APIRouter()


@router.get("/")
def list_devices(
    include_offline: bool = Query(True, description="Include OFFLINE devices"),
    db: Session = Depends(get_db)
):
    """
    Return unified device list from device manager
    Shows single accurate list - no separate "registered" vs "discovered"
    DEFAULT: Shows ALL devices including OFFLINE (changed from False to True)
    """
    from ..device_manager import device_manager
    
    devices = device_manager.get_all_devices(include_offline=include_offline)
    
    device_list = []
    for device in devices:
        # Compute telemetry health in real-time from last_seen
        telemetry_health_score, telemetry_status = compute_telemetry_health(device['last_seen'])
        
        # Display name priority: hostname > vendor > device_type > "Unknown Device"
        display_name = device['hostname'] or device['vendor']
        if not display_name or display_name == "Unknown":
            display_name = device['device_type'].replace('_', ' ').title() if device['device_type'] != 'unknown' else "Unknown Device"
        
        device_list.append({
            "device_id": device['device_id'],
            "name": display_name,
            "device_type": device['device_type'],
            "quarantined": bool(device['quarantined']),
            "last_seen": device['last_seen'].isoformat() if device['last_seen'] else None,
            "last_risk": device['risk_score'],
            "risk_level": device['risk_level'],
            "status": device['status'],
            "ip": device['ip_address'],
            "mac": device['mac_address'],
            "hostname": device['hostname'],
            "vendor": device['vendor'],
            "source": device['source'],
            "telemetry_health_score": telemetry_health_score,
            "telemetry_status": telemetry_status,
        })
    
    return device_list
