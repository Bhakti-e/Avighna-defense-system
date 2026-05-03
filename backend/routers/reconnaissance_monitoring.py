"""
Reconnaissance Monitoring Router
=================================
API endpoints for viewing reconnaissance findings and attack predictions
"""

from fastapi import APIRouter, Query
from .. import state

router = APIRouter()

@router.get("/findings")
def list_reconnaissance_findings(limit: int = Query(50, ge=1, le=200)):
    """
    Get recent reconnaissance findings from active scanner.
    
    Shows:
    - Port scanning detected
    - Brute force setup attempts
    - Lateral movement preparation
    - Network mapping activity
    """
    if not hasattr(state, 'reconnaissance_findings'):
        return {"count": 0, "findings": []}
    
    findings = state.reconnaissance_findings[:limit]
    
    return {
        "count": len(findings),
        "findings": findings,
        "last_scan": findings[0].get("scan_time") if findings else None
    }


@router.get("/indicators/{device_id}")
def get_device_reconnaissance_indicators(device_id: str):
    """
    Get reconnaissance indicators detected for a specific device.
    
    Returns:
    - Current recon risk level
    - Detected indicators (port scan, brute force, etc)
    - Predicted next attack phase
    - Confidence level
    """
    if not hasattr(state, 'reconnaissance_data'):
        return {"device_id": device_id, "data": None}
    
    recon_data = state.reconnaissance_data.get(device_id)
    
    if not recon_data:
        return {
            "device_id": device_id,
            "recon_risk": 0,
            "recon_level": "CLEAR",
            "indicators": []
        }
    
    # Get device status for context
    dev = state.devices.get(device_id, {})
    
    return {
        "device_id": device_id,
        "recon_risk": recon_data.get("recon_risk", 0),
        "recon_level": recon_data.get("recon_level"),
        "indicators": recon_data.get("indicators", []),
        "indicator_count": recon_data.get("indicator_count", 0),
        "confidence": recon_data.get("confidence", 0),
        "estimated_next_phase": recon_data.get("estimated_next_phase"),
        "device_status": dev.get("status"),
        "device_risk": dev.get("last_risk"),
        "timestamp": recon_data.get("timestamp")
    }


@router.get("/threat-timeline")
def get_attack_threat_timeline(hours: int = Query(24, ge=1, le=168)):
    """
    Get timeline of reconnaissance and threat activities.
    
    Shows progression from reconnaissance → exploitation
    """
    import time
    
    if not hasattr(state, 'reconnaissance_findings'):
        return {"timeline": []}
    
    cutoff_time = time.time() - (hours * 3600)
    
    timeline = []
    
    # Get reconnaissance events
    if hasattr(state, 'reconnaissance_findings'):
        for finding in state.reconnaissance_findings:
            if finding.get("scan_time", 0) > cutoff_time:
                threat_indicators = finding.get("threat_indicators", [])
                if threat_indicators:
                    timeline.append({
                        "type": "RECONNAISSANCE",
                        "timestamp": finding.get("scan_time"),
                        "indicators": threat_indicators,
                        "severity": "MEDIUM"
                    })
    
    # Get attack/exploitation alerts
    if hasattr(state, 'alerts'):
        for alert in state.alerts:
            if alert.get("ts", 0) > cutoff_time:
                if alert.get("severity", 0) >= 3:
                    timeline.append({
                        "type": "EXPLOITATION",
                        "timestamp": alert.get("ts"),
                        "device": alert.get("device_id"),
                        "reason": alert.get("reason"),
                        "severity": "CRITICAL"
                    })
    
    # Sort by timestamp
    timeline.sort(key=lambda x: x.get("timestamp", 0))
    
    return {
        "hours_window": hours,
        "timeline": timeline,
        "event_count": len(timeline)
    }


@router.get("/predicted-attacks")
def get_predicted_attacks(min_confidence: float = Query(0.5, ge=0, le=1)):
    """
    Based on reconnaissance patterns, predict which devices might be attacked.
    
    Uses indicators like:
    - Port scanning activity
    - Brute force setup
    - Network enumeration
    
    Returns predicted attack timeline and targets.
    """
    predictions = []
    
    if not hasattr(state, 'reconnaissance_data'):
        return {"predictions": [], "total_at_risk": 0}
    
    for device_id, recon_data in state.reconnaissance_data.items():
        confidence = recon_data.get("confidence", 0)
        risk = recon_data.get("recon_risk", 0)
        
        if confidence >= min_confidence and risk >= 40:
            # Device is showing reconnaissance patterns
            dev = state.devices.get(device_id, {})
            
            predictions.append({
                "device_id": device_id,
                "recon_risk": risk,
                "confidence": confidence,
                "indicators": recon_data.get("indicators", []),
                "estimated_next_phase": recon_data.get("estimated_next_phase"),
                "current_status": dev.get("status"),
                "current_risk": dev.get("last_risk"),
                "recommendation": "Monitor closely, harden services, prepare incident response"
            })
    
    # Sort by risk
    predictions.sort(key=lambda x: x.get("recon_risk", 0), reverse=True)
    
    return {
        "predictions": predictions,
        "total_at_risk": len(predictions),
        "confidence_threshold": min_confidence
    }


@router.get("/early-warning-signs")
def get_early_warning_signs():
    """
    Get all early warning signs of potential attacks.
    
    These are the "thief observing the building" patterns:
    - Port scans
    - Failed login attempts
    - Network probing
    - Service enumeration
    
    Provides time to act BEFORE exploitation.
    """
    warnings = []
    
    if not hasattr(state, 'reconnaissance_findings'):
        return {"early_warnings": [], "action_items": []}
    
    # Check latest findings
    if state.reconnaissance_findings:
        latest = state.reconnaissance_findings[0]
        
        if latest.get("port_scan", {}).get("scan_detected"):
            warnings.append({
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "action": "Review firewall logs, identify scanning source, block if external"
            })
        
        if latest.get("brute_force", {}).get("brute_force_detected"):
            warnings.append({
                "type": "BRUTE_FORCE_PREP",
                "severity": "CRITICAL",
                "action": "Reset credentials, enable MFA, monitor auth logs"
            })
        
        if latest.get("lateral_movement", {}).get("lateral_movement_prep"):
            warnings.append({
                "type": "LATERAL_MOVEMENT_PREP",
                "severity": "HIGH",
                "action": "Segment network, review access controls, monitor internal traffic"
            })
    
    action_items = []
    if warnings:
        action_items = [
            "1. Increase monitoring frequency from 5 to 2 minutes",
            "2. Review access control lists (ACLs)",
            "3. Enable detailed logging on critical services",
            "4. Notify security team and management",
            "5. Prepare incident response plan"
        ]
    
    return {
        "early_warnings": warnings,
        "action_items": action_items,
        "threat_level": "CRITICAL" if len(warnings) > 1 else ("HIGH" if warnings else "LOW")
    }


@router.get("/debug/scapy-status")
def get_scapy_debug_status():
    """
    Debug endpoint to check if Scapy is running and capturing packets
    """
    from ..scanning.scapy_monitor import scapy_monitor
    
    stats = scapy_monitor.get_stats()
    
    return {
        "scapy_running": scapy_monitor.running,
        "interface": scapy_monitor.interface or "default",
        "stats": stats,
        "port_scan_tracking": {
            ip: {
                'ports_seen': len(data['ports']),
                'targets': len(data['targets']),
                'syn_packets': data['syn_packets'],
                'duration': data['last_seen'] - data['first_seen'] if data['first_seen'] > 0 else 0
            }
            for ip, data in scapy_monitor.port_scan_tracking.items()
            if data['syn_packets'] > 0
        },
        "recent_port_scan_alerts": scapy_monitor.port_scan_alerts[-5:] if scapy_monitor.port_scan_alerts else [],
        "arp_table_size": len(scapy_monitor.arp_table)
    }
