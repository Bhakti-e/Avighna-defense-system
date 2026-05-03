"""
Response module
---------------
Contains helpers to perform remediation actions:
- auto_fix(device_id, dev, payload)
- set_under_observation(device_id, dev, params)
- isolate_device(device_id, dev, payload)
- handle_risk_action(device_id, dev, payload, risk)

Uses new forensic PDF reports for evidence documentation
"""
import time
import uuid
from typing import Dict, Any, Optional
from .utils.quarantine import block_ip, disconnect_wifi, isolate_device_completely
from .utils.observation import apply_observation
from . import state
from .core.pdf_reports import generate_isolation_report


def auto_fix(device_id: str, dev: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    """Attempt simple auto-fixes (demo). Returns action summary."""
    actions = {"device_id": device_id, "actions": [], "ts": time.time()}

    # Example auto-fix: if suspicious file path present, attempt to remove (demo placeholder)
    suspicious = payload.get("suspicious_file") or (payload.get("extra") or {}).get("suspicious_file")
    if suspicious:
        try:
            # Demo: we won't delete any file; just record attempt
            actions["actions"].append({"action": "mark_file_for_analysis", "path": suspicious})
        except Exception as e:
            actions["actions"].append({"action": "mark_file_failed", "error": str(e)})

    # Example: if many failed logins, recommend password reset (simulation)
    if payload.get("failed_logins", 0) >= 5:
        actions["actions"].append({"action": "recommend_password_reset", "reason": "multiple_failed_logins"})

    return actions


def set_under_observation(device_id: str, dev: Dict[str, Any], params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Place device under observation (limit bandwidth, restrict outbound)."""
    params = params or {}
    observation_timestamp = time.time()
    
    dev["status"] = "UNDER_OBSERVATION"
    dev.setdefault("observation", {})
    dev["observation"]["start"] = observation_timestamp
    dev["observation"]["reason"] = params.get("reason", "Auto observation due to elevated risk")
    dev["observation"]["limit_kbps"] = params.get("limit_kbps", 100)
    dev["observation"]["allowed_outbound"] = params.get("allowed_outbound", [])
    
    # Enhanced observation tracking
    dev["observation"]["details"] = {
        "observed_by": "DOME Monitoring System",
        "observation_method": "Automated Threat Detection",
        "observation_timestamp": observation_timestamp,
        "restrictions_applied": [],
        "monitoring_level": "Enhanced"
    }
    
    # Track what restrictions were applied
    dev["observation"]["details"]["restrictions_applied"].append(f"Bandwidth limited to {dev['observation']['limit_kbps']} kbps")
    if dev["observation"]["allowed_outbound"]:
        dev["observation"]["details"]["restrictions_applied"].append(f"Outbound access restricted to: {', '.join(dev['observation']['allowed_outbound'])}")
    else:
        dev["observation"]["details"]["restrictions_applied"].append("All outbound connections restricted")

    # Apply simulated observation actions
    try:
        actions = apply_observation(device_id, ip=dev.get("ip"), params={"limit_kbps": dev["observation"]["limit_kbps"], "allowed_ips": dev["observation"]["allowed_outbound"]})
        dev["observation_actions"] = actions
        dev["observation"]["details"]["restrictions_applied"].append("Network traffic monitoring activated")
    except Exception as e:
        dev["observation_error"] = str(e)
        dev["observation"]["details"]["restrictions_applied"].append(f"Failed to apply network restrictions: {str(e)}")

    # Log an alert
    obs_alert = {
        "id": str(uuid.uuid4()),
        "device_id": device_id,
        "reason": dev["observation"]["reason"],
        "severity": 2,
        "action": "auto_observe",
        "observation_details": dev["observation"]["details"].copy(),
        "ts": observation_timestamp,
    }
    state.alerts.insert(0, obs_alert)

    return {"status": "observed", "device_id": device_id, "actions": dev.get("observation_actions"), "observation_details": dev["observation"]["details"]}


def isolate_device(device_id: str, dev: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    """Perform strong isolation/quarantine and collect forensics. Returns details including forensics path."""
    isolation_timestamp = time.time()
    
    dev["quarantined"] = True
    dev["status"] = "ISOLATED"
    dev["quarantine_time"] = isolation_timestamp
    
    # Enhanced isolation tracking
    dev["isolation_details"] = {
        "isolated_by": "DOME Auto-Defense System",
        "isolation_method": "Automated Risk Assessment",
        "isolation_timestamp": isolation_timestamp,
        "isolation_reason": "Critical risk threshold exceeded",
        "risk_score_at_isolation": payload.get("risk_score", 0),
        "trigger_events": [],
        "network_actions_taken": [],
        "forensics_collected": False,
        "backup_status": "pending"
    }
    
    # Track what triggered the isolation
    if payload.get("failed_logins", 0) > 0:
        dev["isolation_details"]["trigger_events"].append(f"Failed login attempts: {payload.get('failed_logins')}")
    if payload.get("connections", 0) > 10:
        conn_count = payload.get("connections") if isinstance(payload.get("connections"), int) else len(payload.get("connections", []))
        dev["isolation_details"]["trigger_events"].append(f"Excessive network connections: {conn_count}")
    if payload.get("bytes_out", 0) > 1000000:
        mb_out = payload.get("bytes_out") / 1000000
        dev["isolation_details"]["trigger_events"].append(f"High data transfer: {mb_out:.1f} MB")
    if payload.get("suspicious_file"):
        dev["isolation_details"]["trigger_events"].append(f"Suspicious file detected: {payload.get('suspicious_file')}")
    if payload.get("outbound_ips"):
        risky_ips = [ip for ip in payload.get("outbound_ips", []) if any(ip.startswith(p) for p in ("45.", "89.", "185.", "103.", "91."))]
        if risky_ips:
            dev["isolation_details"]["trigger_events"].append(f"Communication with risky IPs: {', '.join(risky_ips)}")

    ip = dev.get("ip") or dev.get("last_ip")
    mac = dev.get("mac") or device_id

    actions = {"blocked_ip": None, "wifi_disconnected": None}

    if ip:
        try:
            block_ip(ip)
            actions["blocked_ip"] = ip
            dev["isolation_details"]["network_actions_taken"].append(f"Blocked IP address: {ip}")
        except Exception as e:
            actions["block_error"] = str(e)
            dev["isolation_details"]["network_actions_taken"].append(f"Failed to block IP {ip}: {str(e)}")

    try:
        disconnect_wifi(mac)
        actions["wifi_disconnected"] = mac
        dev["isolation_details"]["network_actions_taken"].append(f"Disconnected WiFi for device: {mac}")
    except Exception as e:
        actions["wifi_error"] = str(e)
        dev["isolation_details"]["network_actions_taken"].append(f"Failed to disconnect WiFi for {mac}: {str(e)}")

    # optional: call deeper network isolation helper
    try:
        isolate_report = isolate_device_completely(device_id, ip=ip, mac=mac)
        actions["isolate_report"] = isolate_report
        if isolate_report and isolate_report.get("actions"):
            for action in isolate_report["actions"]:
                dev["isolation_details"]["network_actions_taken"].append(f"Network isolation: {action.get('action', 'unknown')} - {action.get('status', 'unknown')}")
    except Exception:
        pass

    # create quarantine alert
    qalert = {
        "id": str(uuid.uuid4()),
        "device_id": device_id,
        "reason": "AUTO-QUARANTINE: device isolated due to critical risk",
        "severity": 4,
        "action": "auto_quarantine",
        "actions": actions,
        "isolation_details": dev["isolation_details"].copy(),  # Include isolation details in alert
        "ts": isolation_timestamp,
    }
    state.alerts.insert(0, qalert)

    # collect forensics bundle and generate PDF report
    try:
        # Get server URL from config or use localhost
        from ..config import settings
        import socket
        
        # Try to get local IP address
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "localhost"
        
        server_url = f"http://{local_ip}:8000"
        
        # Prepare device info for PDF
        device_info = {
            'ip': dev.get('ip', 'Unknown'),
            'mac': dev.get('mac', device_id),
            'vendor': dev.get('vendor', 'Unknown'),
            'brand': dev.get('brand', 'Unknown Device')
        }
        
        # Prepare isolation details
        isolation_details = {
            'timestamp': isolation_timestamp,
            'reason': dev["isolation_details"]["isolation_reason"],
            'malware_type': 'Generic Malware',  # Will be enhanced with YARA results
            'malware_version': 'Unknown',
            'risk_score': payload.get('risk_score', dev.get('last_risk', 0)),
            'file_hash': None  # Will be populated if suspicious file detected
        }
        
        # Extract malware info from payload if available
        if payload.get('suspicious_file'):
            isolation_details['file_hash'] = 'a' * 64  # Placeholder, will be real SHA256
        
        # Generate forensic PDF report
        pdf_path = generate_isolation_report(
            device_id=device_id,
            device_info=device_info,
            isolation_details=isolation_details,
            download_url=None  # Will be set after PDF is generated
        )
        
        if pdf_path:
            # Extract filename and create download URL
            import os
            pdf_filename = os.path.basename(pdf_path)
            download_url = f"{server_url}/reports/download/{pdf_filename}"
            
            # Regenerate PDF with actual download URL
            pdf_path = generate_isolation_report(
                device_id=device_id,
                device_info=device_info,
                isolation_details=isolation_details,
                download_url=download_url
            )
            
            qalert["forensics_path"] = pdf_path
            qalert["download_url"] = download_url
            dev["isolation_details"]["forensics_collected"] = True
            dev["isolation_details"]["forensics_path"] = pdf_path
            dev["isolation_details"]["pdf_report"] = pdf_path
            dev["isolation_details"]["download_url"] = download_url
    except Exception as e:
        import logging
        logging.getLogger('avighna').error(f"PDF report generation failed: {e}")

    # Update backup status
    dev["isolation_details"]["backup_status"] = "completed" if dev["isolation_details"]["forensics_collected"] else "failed"

    return {"status": "isolated", "device_id": device_id, "actions": actions, "forensics_path": qalert.get("forensics_path"), "isolation_details": dev["isolation_details"]}


def handle_risk_action(device_id: str, dev: Dict[str, Any], payload: Dict[str, Any], risk: Dict[str, Any], recon: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Decide action based on risk score and perform it. Returns action summary."""
    score = risk.get("risk_score", 0)
    res = {"device_id": device_id, "score": score, "actions": []}

    # If moderate to high recon indicators, attach to dev for context
    if recon:
        dev["recon"] = recon

    # Try auto-fix where possible (low cost)
    fix = auto_fix(device_id, dev, payload)
    if fix and fix.get("actions"):
        res["actions"].append({"auto_fix": fix})

    # 40-69 -> UNDER_OBSERVATION
    if 40 <= score < 70:
        obs = set_under_observation(device_id, dev, params={"limit_kbps": 100, "allowed_outbound": [], "reason": "Auto observation: elevated risk"})
        res["actions"].append({"observation": obs})

    # If Recon indicates suspicious activity even when numeric score is lower, consider observation or isolation
    if recon and isinstance(recon, dict):
        r_risk = recon.get("recon_risk", 0)
        # low-to-moderate recon risk: observe
        if r_risk >= 20 and score < 40:
            obs = set_under_observation(device_id, dev, params={"limit_kbps": 100, "allowed_outbound": [], "reason": "Auto observation: recon indicators detected"})
            res["actions"].append({"observation": obs})
        # high recon risk: isolate if not already isolated
        if r_risk >= 70 and score < 70:
            iso = isolate_device(device_id, dev, payload)
            res["actions"].append({"isolate": iso})

    # >=70 -> ISOLATE
    if score >= 70:
        iso = isolate_device(device_id, dev, payload)
        res["actions"].append({"isolate": iso})

    return res
