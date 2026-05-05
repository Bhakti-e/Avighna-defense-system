"""
Manual Device Registration API
Allows users to manually register devices for monitoring
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel, validator
from typing import Optional
import re
import subprocess
import socket
from datetime import datetime

from ..database import get_db
from .. import models

router = APIRouter()


class ManualDeviceCreate(BaseModel):
    """Manual device registration request"""
    nickname: str
    mac_address: str
    ip_address: Optional[str] = None
    device_type: str = "unknown"
    
    @validator('mac_address')
    def validate_mac(cls, v):
        """Validate MAC address format"""
        # Remove common separators
        mac = v.lower().replace(':', '').replace('-', '').replace('.', '')
        
        # Check if valid hex and correct length
        if not re.match(r'^[0-9a-f]{12}$', mac):
            raise ValueError('Invalid MAC address format. Use format: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF')
        
        # Convert to standard format (lowercase with dashes)
        formatted = '-'.join([mac[i:i+2] for i in range(0, 12, 2)])
        return formatted
    
    @validator('nickname')
    def validate_nickname(cls, v):
        """Validate nickname"""
        if not v or len(v.strip()) == 0:
            raise ValueError('Device nickname is required')
        if len(v) > 100:
            raise ValueError('Nickname too long (max 100 characters)')
        return v.strip()
    
    @validator('device_type')
    def validate_device_type(cls, v):
        """Validate device type"""
        valid_types = ['router', 'phone', 'laptop', 'tablet', 'iot', 'server', 'unknown']
        if v not in valid_types:
            raise ValueError(f'Invalid device type. Must be one of: {", ".join(valid_types)}')
        return v


class ConnectivityCheckResponse(BaseModel):
    """Connectivity check response"""
    online: bool
    ip_address: Optional[str]
    response_time_ms: Optional[float]
    message: str


def check_device_on_network(mac: str, ip: Optional[str] = None) -> dict:
    """
    Check if device exists on network using ARP table
    Returns: {exists: bool, ip: str or None, message: str}
    """
    try:
        # Run arp -a to get ARP table
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
            errors="ignore"
        )
        
        if result.returncode != 0:
            return {"exists": False, "ip": None, "message": "Failed to read ARP table"}
        
        # Parse ARP output to find MAC
        mac_normalized = mac.lower().replace('-', ':')
        
        for line in result.stdout.splitlines():
            # Look for MAC address in line
            if mac_normalized in line.lower() or mac.lower() in line.lower():
                # Extract IP from line
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    found_ip = ip_match.group(1)
                    return {
                        "exists": True,
                        "ip": found_ip,
                        "message": f"Device found on network at {found_ip}"
                    }
        
        return {
            "exists": False,
            "ip": None,
            "message": "Device not found in ARP table. Device may be offline or not on this network."
        }
    
    except Exception as e:
        return {"exists": False, "ip": None, "message": f"Network check failed: {str(e)}"}


def ping_device(ip: str) -> dict:
    """
    Ping device to check connectivity
    Returns: {online: bool, response_time_ms: float or None, message: str}
    """
    try:
        # Determine ping command based on OS
        import platform
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        
        # Run ping command
        result = subprocess.run(
            ['ping', param, '1', ip],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
            errors="ignore"
        )
        
        if result.returncode == 0:
            # Extract response time from output
            time_match = re.search(r'time[=<](\d+\.?\d*)\s*ms', result.stdout, re.IGNORECASE)
            response_time = float(time_match.group(1)) if time_match else None
            
            return {
                "online": True,
                "response_time_ms": response_time,
                "message": f"Device is online (response time: {response_time}ms)" if response_time else "Device is online"
            }
        else:
            return {
                "online": False,
                "response_time_ms": None,
                "message": "Device is offline or not responding to ping"
            }
    
    except subprocess.TimeoutExpired:
        return {
            "online": False,
            "response_time_ms": None,
            "message": "Ping timeout - device may be offline"
        }
    except Exception as e:
        return {
            "online": False,
            "response_time_ms": None,
            "message": f"Connectivity check failed: {str(e)}"
        }


@router.post("/register")
def register_manual_device(device: ManualDeviceCreate, force: bool = False, db: Session = Depends(get_db)):
    """
    Register a device manually with optional verification
    
    Verification steps (if force=False):
    1. Check ARP table for MAC address
    2. Determine IP (prefer ARP-verified over user-provided)
    3. PING device to verify it's online (OPTIONAL - can be skipped with force=True)
    4. Verify MAC-IP binding matches
    
    If force=True: Skip ping check, register anyway (for offline/sleeping devices)
    """
    # Check if device already exists
    existing = db.query(models.Device).filter(
        models.Device.device_id == device.mac_address
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Device with MAC {device.mac_address} already registered"
        )
    
    # STEP 1: Check ARP table
    network_check = check_device_on_network(device.mac_address, device.ip_address)
    
    # STEP 2: Determine IP (prefer ARP-found IP over user-provided)
    if network_check.get('exists'):
        final_ip = network_check.get('ip')  # Use ARP-verified IP
        
        # If user provided different IP, warn about mismatch
        if device.ip_address and device.ip_address != final_ip:
            raise HTTPException(
                status_code=400,
                detail=f"MAC/IP mismatch: ARP table shows {final_ip}, you provided {device.ip_address}. Using ARP-verified IP."
            )
    elif device.ip_address:
        final_ip = device.ip_address
    else:
        raise HTTPException(
            status_code=400,
            detail="Device not found in ARP table. Please provide IP address or ensure device is connected to the network."
        )
    
    # STEP 3: PING VERIFICATION (OPTIONAL - can be skipped)
    ping_verified = False
    ping_message = "Ping check skipped (force registration)"
    response_time_ms = None
    device_status = "OFFLINE"  # Default for force registration
    
    if not force:
        ping_result = ping_device(final_ip)
        ping_verified = ping_result['online']
        ping_message = ping_result['message']
        response_time_ms = ping_result.get('response_time_ms')
        
        if not ping_verified:
            raise HTTPException(
                status_code=400,
                detail=f"Device not responding to ping: {ping_message}. Use force=True query parameter to register anyway (for sleeping/offline devices)."
            )
        device_status = "ACTIVE"
    else:
        # Force registration - mark as offline but allow registration
        device_status = "OFFLINE"
        ping_message = "Device registered without ping verification (may be sleeping/offline)"
    
    # STEP 4: Create device record
    now = datetime.utcnow()
    new_device = models.Device(
        device_id=device.mac_address,
        ip_address=final_ip,
        mac_address=device.mac_address,
        hostname=device.nickname,
        vendor="Unknown",  # Will be looked up by device manager
        source="manual",
        status=device_status,
        risk_score=0.0,
        risk_level="GREEN",
        first_seen=now,
        last_seen=now,
        quarantined=0
    )
    
    db.add(new_device)
    db.commit()
    db.refresh(new_device)
    
    return {
        "success": True,
        "message": "Device registered successfully" + (" (forced - no ping verification)" if force else " with verification"),
        "device": {
            "device_id": new_device.device_id,
            "nickname": device.nickname,
            "mac_address": device.mac_address,
            "ip_address": final_ip,
            "device_type": device.device_type,
            "status": new_device.status,
            "verification": {
                "arp_verified": network_check.get('exists'),
                "ping_verified": ping_verified,
                "response_time_ms": response_time_ms,
                "message": ping_message,
                "forced_registration": force
            }
        }
    }


@router.post("/check-connectivity")
def check_connectivity(mac_address: str, ip_address: Optional[str] = None, db: Session = Depends(get_db)):
    """
    Check device connectivity
    Returns online status and response time
    """
    # Validate MAC format
    try:
        mac = mac_address.lower().replace(':', '-').replace('.', '')
        mac = '-'.join([mac[i:i+2] for i in range(0, 12, 2)])
    except:
        raise HTTPException(status_code=400, detail="Invalid MAC address format")
    
    # Check network presence
    network_check = check_device_on_network(mac, ip_address)
    
    # Use provided IP or found IP
    target_ip = ip_address or network_check.get('ip')
    
    if not target_ip:
        return ConnectivityCheckResponse(
            online=False,
            ip_address=None,
            response_time_ms=None,
            message="Device not found on network"
        )
    
    # Ping device
    ping_result = ping_device(target_ip)
    
    return ConnectivityCheckResponse(
        online=ping_result['online'],
        ip_address=target_ip,
        response_time_ms=ping_result.get('response_time_ms'),
        message=ping_result['message']
    )


@router.get("/manual")
def list_manual_devices(db: Session = Depends(get_db)):
    """
    List all manually registered devices
    """
    devices = db.query(models.Device).filter(
        models.Device.source == "manual"
    ).all()
    
    return [
        {
            "device_id": d.device_id,
            "nickname": d.hostname,
            "mac_address": d.mac_address,
            "ip_address": d.ip_address,
            "vendor": d.vendor,
            "status": d.status,
            "risk_level": d.risk_level,
            "first_seen": d.first_seen.isoformat() if d.first_seen else None,
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        }
        for d in devices
    ]


@router.post("/test-live-connection")
def test_live_connection(
    mac_address: str,
    ip_address: str,
    db: Session = Depends(get_db)
):
    """
    Comprehensive connectivity test before registration
    
    Tests:
    1. Ping device
    2. Verify ARP mapping
    3. Check if Scapy has detected traffic
    
    Returns confidence score 0-100
    """
    results = {
        "ping_success": False,
        "arp_verified": False,
        "packet_detected": False,
        "ports_open": [],
        "confidence_score": 0,
        "details": {},
        "recommendation": ""
    }
    
    # Validate MAC format
    try:
        mac = mac_address.lower().replace(':', '-').replace('.', '')
        mac = '-'.join([mac[i:i+2] for i in range(0, 12, 2)])
    except:
        raise HTTPException(status_code=400, detail="Invalid MAC address format")
    
    # Test 1: Ping (40 points)
    ping_result = ping_device(ip_address)
    results["ping_success"] = ping_result['online']
    results["details"]["ping"] = ping_result
    
    if results["ping_success"]:
        results["confidence_score"] += 40
    
    # Test 2: ARP verification (30 points)
    arp_check = check_device_on_network(mac, ip_address)
    results["arp_verified"] = arp_check.get('exists', False)
    results["details"]["arp"] = arp_check
    
    if results["arp_verified"]:
        results["confidence_score"] += 30
        
        # Check if ARP IP matches provided IP
        if arp_check.get('ip') and arp_check.get('ip') != ip_address:
            results["details"]["arp_warning"] = f"MAC found at different IP: {arp_check.get('ip')}"
            results["confidence_score"] -= 10
    
    # Test 3: Scapy packet detection (30 points)
    try:
        from ..scanning.scapy_monitor import scapy_monitor
        
        # Check if device has been seen in Scapy's ARP table
        scapy_devices = scapy_monitor.get_discovered_devices()
        for dev in scapy_devices:
            if dev['ip'] == ip_address or dev['mac'].upper() == mac.upper().replace('-', ':'):
                results["packet_detected"] = True
                results["confidence_score"] += 30
                results["details"]["scapy"] = {
                    "last_seen": dev['last_seen'],
                    "packet_count": dev['packet_count'],
                    "vendor": dev['vendor']
                }
                break
        
        if not results["packet_detected"]:
            results["details"]["scapy"] = {"message": "No traffic detected from this device yet"}
    
    except Exception as e:
        results["details"]["scapy_error"] = f"Scapy monitoring not available: {str(e)}"
    
    # Generate recommendation
    if results["confidence_score"] >= 70:
        results["recommendation"] = "HIGH CONFIDENCE - Device is verified online and reachable. Safe to register."
    elif results["confidence_score"] >= 40:
        results["recommendation"] = "MEDIUM CONFIDENCE - Device responds to ping but limited verification. Registration allowed but monitor closely."
    else:
        results["recommendation"] = "LOW CONFIDENCE - Device may be offline or unreachable. Registration will likely fail."
    
    return results


@router.delete("/{device_id}")
def delete_manual_device(device_id: str, db: Session = Depends(get_db)):
    """
    Delete a manually registered device
    """
    device = db.query(models.Device).filter(
        models.Device.device_id == device_id,
        models.Device.source == "manual"
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=404,
            detail="Manual device not found"
        )
    
    db.delete(device)
    db.commit()
    
    return {"success": True, "message": "Device deleted successfully"}
