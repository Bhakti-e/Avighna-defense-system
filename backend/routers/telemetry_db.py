# backend/routers/telemetry_db.py
"""
Telemetry router with DATABASE integration
Replaces in-memory state with SQLAlchemy ORM
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union
import time, uuid, os, shutil
import logging
from .. import state  # Keep for backward compatibility with background tasks
from ..database import get_db
from ..db_utils import (
    get_or_create_device, update_device_last_seen, update_device_risk,
    create_alert, create_telemetry_record, update_device_baseline,
    set_device_isolated, set_device_under_observation
)
from ..core.risk_scoring import compute_risk, score_to_level
from .. import profile
from ..utils.quarantine import block_ip, disconnect_wifi
from ..core.reconnaissance import ReconnaissanceDetector, predict_attack_phase
from ..core.forensics import forensics_engine
from ..core.ml_detection import enhanced_ml_engine
from ..scanning.active_scanner import active_scanner
from ..core.cti import cti_manager
from ..config import settings

# Initialize logger
logger = logging.getLogger(__name__)

router = APIRouter()

# configurable risky IP prefixes
RISKY_PREFIXES = ("45.", "89.", "185.", "103.", "91.")


class TelemetryIn(BaseModel):
    device_id: str
    failed_logins: int = 0
    connections: Union[int, List[Dict[str, Any]]] = 0
    outbound_ips: List[str] = []
    bytes_out: int = 0
    suspicious_file: Optional[str] = None
    events: List[Dict[str, Any]] = Field(default_factory=list)
    recon_indicators: Dict[str, int] = Field(default_factory=dict)
    anomaly_score: Optional[float] = None
    extra: Dict[str, Any] = Field(default_factory=dict)
    ts: float = Field(default_factory=lambda: time.time())


def _detect_rules(t: TelemetryIn):
    """Rule-based detection - returns (reason, severity)"""
    reasons = []
    severity = 0

    if t.failed_logins >= 2:
        reasons.append(f"{t.failed_logins} failed login attempt(s)")
        severity = max(severity, 2)

    conn_count = t.connections if isinstance(t.connections, int) else (len(t.connections) if t.connections else 0)
    if conn_count > 8:
        reasons.append(f"{conn_count} outbound connection(s)")
        severity = max(severity, 2)
    if t.bytes_out > 5_000_000:
        reasons.append(f"High outbound bytes: {t.bytes_out:,}")
        severity = max(severity, 2)

    if t.suspicious_file:
        reasons.append(f"Suspicious file: {t.suspicious_file}")
        severity = max(severity, 3)

    risky = [ip for ip in t.outbound_ips if any(ip.startswith(p) for p in RISKY_PREFIXES)]
    if risky:
        reasons.append(f"Outbound to risky IP(s): {', '.join(risky)}")
        severity = max(severity, 3)

    if reasons:
        return ("; ".join(reasons), severity)
    return (None, 0)


def _simulate_backup(device_id: str, payload: TelemetryIn) -> Dict[str, Any]:
    """Simulate file backup for isolated devices"""
    important_files = payload.extra.get("important_files", [])
    backup_root = os.path.join("backups", device_id)
    os.makedirs(backup_root, exist_ok=True)
    backed_up = []

    for path in important_files:
        filename = os.path.basename(path) or "unknown_file"
        dst = os.path.join(backup_root, filename)
        try:
            if os.path.isfile(path):
                shutil.copy2(path, dst)
            else:
                with open(dst, "w", encoding="utf-8") as f:
                    f.write(f"Placeholder backup for {path}\n")
            backed_up.append(dst)
        except Exception:
            continue

    return {
        "backup_started": bool(important_files),
        "backup_folder": backup_root if important_files else None,
        "backed_up_files": backed_up,
        "requested_files": important_files,
    }


@router.post("/ingest")
def ingest(payload: TelemetryIn, db: Session = Depends(get_db)):
    """
    Main telemetry ingestion endpoint with DATABASE storage
    
    Pipeline:
    1. Get/create device (set first_seen, update last_seen)
    2. Store telemetry_history record
    3. Rule-based detection
    4. Reconnaissance detection
    5. Forensics analysis
    6. Enhanced ML prediction
    7. Baseline profile update
    8. Risk computation
    9. Response actions (observe/isolate)
    10. Alert creation if needed
    """
    
    # STEP 1: Get or create device in DB
    device = get_or_create_device(
        db, 
        payload.device_id,
        ip_address=payload.extra.get("ip"),
        source="agent"
    )
    
    # Update last_seen timestamp
    update_device_last_seen(db, payload.device_id)
    
    # Check if device is quarantined
    if device.quarantined:
        raise HTTPException(status_code=423, detail="Device is quarantined")
    
    # STEP 2: Store telemetry history for baseline computation
    telemetry_record = create_telemetry_record(db, payload.device_id, payload.model_dump())
    
    # STEP 3: Rule-based detection
    reason, severity = _detect_rules(payload)
    
    # STEP 4: Build history for reconnaissance detection (keep in-memory for now)
    hist = state.device_history.get(payload.device_id, [])
    conn_count = payload.connections if isinstance(payload.connections, int) else (len(payload.connections) if payload.connections else 0)
    
    if conn_count > 20:
        event_type = "port_probe"
    elif conn_count > 8:
        event_type = "suspicious_connection"
    elif payload.failed_logins > 0:
        event_type = "auth_failure"
    else:
        event_type = "normal"
    
    hist.append((time.time(), event_type, {
        "connections": payload.connections, 
        "bytes_out": payload.bytes_out, 
        "outbound_ips": payload.outbound_ips
    }))
    hist = hist[-1000:]
    state.device_history[payload.device_id] = hist
    
    # Build device data for reconnaissance detector
    device_data = {
        "failed_logins": payload.failed_logins,
        "connections": payload.connections,
        "bytes_out": payload.bytes_out,
        "outbound_ips": payload.outbound_ips,
        "auth_attempts": payload.extra.get("auth_attempts", []),
        "arp_requests": payload.extra.get("arp_requests", []),
        "dns_queries": payload.extra.get("dns_queries", []),
        "nmap_results": payload.extra.get("nmap_results", {})
    }
    
    # Parse event-based telemetry
    try:
        events = getattr(payload, "events", None) or payload.extra.get("events", [])
        if events:
            conn_list = []
            for ev in events:
                t = ev.get("type", "").lower()
                if t == "port_scan":
                    ports = ev.get("ports", []) or ev.get("port_list", [])
                    for p in ports:
                        conn_list.append({
                            "target_ip": payload.extra.get("ip") or payload.device_id, 
                            "port": int(p), 
                            "status": "closed", 
                            "ts": time.time()
                        })
                elif t in ("suspicious_recon", "port_probe"):
                    ports = ev.get("ports", [])
                    for p in ports:
                        conn_list.append({
                            "target_ip": payload.extra.get("ip") or payload.device_id, 
                            "port": int(p), 
                            "status": "closed", 
                            "ts": time.time()
                        })
                elif t in ("auth_failure", "failed_login"):
                    aa = ev.get("attempts", [])
                    if aa:
                        device_data["auth_attempts"].extend(aa)
                elif t == "arp_probe":
                    device_data["arp_requests"].extend(ev.get("targets", []))
            
            if isinstance(device_data.get("connections"), list):
                device_data["connections"] = device_data.get("connections", []) + conn_list
            elif isinstance(device_data.get("connections"), int) and conn_list:
                device_data["connections"] = conn_list
    except Exception:
        pass
    
    # STEP 5: RECONNAISSANCE DETECTION
    recon_detector = ReconnaissanceDetector()
    recon_data = recon_detector.compute_reconnaissance_score(payload.device_id, device_data)
    
    # Add active scanning reconnaissance data
    device_ip = device.ip_address
    if device_ip:
        active_recon_score = active_scanner.get_recon_score_for_ip(device_ip)
        if active_recon_score > 0:
            recon_data["active_scan_score"] = active_recon_score
            recon_data["recon_risk"] = max(recon_data.get("recon_risk", 0), active_recon_score)
            if not recon_data.get("indicators"):
                recon_data["indicators"] = []
            recon_data["indicators"].append(f"Active network scanning detected (score: {active_recon_score:.1f})")
    
    # Predict attack phase if reconnaissance detected
    attack_prediction = None
    if recon_data.get("recon_risk", 0) >= 40:
        attack_prediction = predict_attack_phase(recon_data)
    
    # Handle client-declared recon indicators
    try:
        declared = getattr(payload, 'recon_indicators', None) or payload.extra.get('recon_indicators')
        if declared and isinstance(declared, dict):
            keys = [k for k, v in declared.items() if v]
            recon_data.setdefault('indicators', [])
            recon_data['indicators'].extend(keys)
            recon_data['indicator_count'] = len(recon_data.get('indicators', []))
            recon_data['recon_risk'] = max(recon_data.get('recon_risk', 0), 20.0)
            
            if 'exploit' in declared and declared.get('exploit'):
                recon_data['recon_risk'] = max(recon_data.get('recon_risk', 0), 85.0)
                recon_data['recon_level'] = 'CRITICAL'
            else:
                if recon_data['recon_risk'] >= 40:
                    recon_data['recon_level'] = 'CRITICAL'
                elif recon_data['recon_risk'] >= 20:
                    recon_data['recon_level'] = 'SUSPICIOUS'
    except Exception:
        pass
    
    # Store reconnaissance data (keep in-memory for now)
    if not hasattr(state, "reconnaissance_data"):
        state.reconnaissance_data = {}
    state.reconnaissance_data[payload.device_id] = recon_data
    
    # Add to reconnaissance findings
    try:
        if not hasattr(state, 'reconnaissance_findings'):
            state.reconnaissance_findings = []
        
        if recon_data and (recon_data.get('indicator_count', 0) > 0 or recon_data.get('recon_risk', 0) > 0):
            finding = {
                'scan_time': recon_data.get('timestamp', time.time()),
                'device_id': payload.device_id,
                'threat_indicators': recon_data.get('indicators', []),
                'recon_risk': recon_data.get('recon_risk', 0),
                'recon_level': recon_data.get('recon_level')
            }
            state.reconnaissance_findings.insert(0, finding)
            state.reconnaissance_findings = state.reconnaissance_findings[:100]
    except Exception:
        pass
    
    # STEP 6: FORENSICS ANALYSIS (YARA + PE + Heuristics)
    forensics_score = 0.0
    forensics_results = []
    yara_detections = []  # Always initialize as empty list
    
    # CTI THREAT INTELLIGENCE CHECK
    cti_threats = []
    cti_boost = 0.0
    
    # Check outbound IPs against CTI feeds
    for ip in payload.outbound_ips:
        cti_result = cti_manager.check_ip(ip)
        if cti_result.get("is_malicious"):
            cti_threats.append({
                "type": "ip",
                "value": ip,
                "threat_type": cti_result.get("threat_type"),
                "malware_family": cti_result.get("malware_family"),
                "confidence": cti_result.get("confidence"),
                "source": cti_result.get("source"),
                "recommendation": cti_result.get("recommendation")
            })
            # Boost risk based on confidence
            if cti_result.get("confidence") == "high":
                cti_boost += 30.0
            elif cti_result.get("confidence") == "medium":
                cti_boost += 20.0
            else:
                cti_boost += 10.0
            
            logger.warning(f"CTI THREAT: Device {payload.device_id} contacted malicious IP {ip} - "
                          f"{cti_result.get('threat_type')} ({cti_result.get('malware_family')})")
    
    print(f"DEBUG: suspicious_file = {payload.suspicious_file}")  # DEBUG
    
    if payload.suspicious_file:
        print(f"DEBUG: Starting forensics analysis...")  # DEBUG
        try:
            logger.info(f"Starting forensics analysis for file: {payload.suspicious_file}")
            forensics_result = forensics_engine.analyze_file(payload.suspicious_file)
            forensics_score = forensics_result.threat_score
            print(f"DEBUG: Forensics complete - score={forensics_score}, detections={len(forensics_result.detections)}")  # DEBUG
            logger.info(f"Forensics analysis complete: threat_score={forensics_score}, detections={len(forensics_result.detections)}")
            
            # Extract YARA-specific detections (always returns list, never None)
            for detection in forensics_result.detections:
                logger.info(f"Detection found: tool={detection.get('tool')}, rule={detection.get('rule')}")
                print(f"DEBUG: Detection - tool={detection.get('tool')}, rule={detection.get('rule')}")  # DEBUG
                if detection.get('tool') == 'YARA':
                    yara_detections.append(detection)
                    logger.info(f"YARA detection added: {detection.get('rule')}")
                    print(f"DEBUG: YARA detection added!")  # DEBUG
            
            forensics_results.append({
                "file": payload.suspicious_file,
                "threat_score": forensics_result.threat_score,
                "threat_level": forensics_result.threat_level,
                "detections": forensics_result.detections[:10],  # Limit for display
                "confidence": forensics_result.confidence,
                "yara_matches": len(yara_detections)  # Count of YARA matches (0 if none)
            })
            
            # CTI: Check file hash against threat feeds and VirusTotal
            try:
                file_info = forensics_result.file_info
                file_hash = file_info.get("sha256")
                
                if file_hash:
                    # Check CTI feeds
                    cti_hash_result = cti_manager.check_file_hash(file_hash)
                    if cti_hash_result.get("is_malicious"):
                        cti_threats.append({
                            "type": "file_hash",
                            "value": file_hash,
                            "file": payload.suspicious_file,
                            "threat_type": cti_hash_result.get("threat_type"),
                            "source": cti_hash_result.get("source"),
                            "recommendation": cti_hash_result.get("recommendation")
                        })
                        cti_boost += 40.0
                        logger.warning(f"CTI THREAT: Known malware hash detected - {file_hash}")
                    
                    # Check VirusTotal (if API key configured)
                    vt_result = cti_manager.check_virustotal(file_hash)
                    if vt_result.get("is_malicious"):
                        cti_threats.append({
                            "type": "virustotal",
                            "value": file_hash,
                            "file": payload.suspicious_file,
                            "detection_ratio": vt_result.get("detection_ratio"),
                            "threat_names": vt_result.get("threat_names", []),
                            "confidence": vt_result.get("confidence"),
                            "source": "VirusTotal",
                            "recommendation": vt_result.get("recommendation")
                        })
                        # Boost based on detection ratio
                        malicious_count = vt_result.get("malicious_count", 0)
                        if malicious_count > 10:
                            cti_boost += 50.0
                        elif malicious_count > 3:
                            cti_boost += 30.0
                        else:
                            cti_boost += 15.0
                        
                        logger.warning(f"VirusTotal DETECTION: {vt_result.get('detection_ratio')} - "
                                     f"{', '.join(vt_result.get('threat_names', [])[:3])}")
            except Exception as e:
                logger.error(f"CTI hash check failed: {e}")
            
            # Store detailed forensics data
            if not hasattr(state, "forensics_data"):
                state.forensics_data = {}
            state.forensics_data[payload.device_id] = forensics_result
            
            # Log YARA detections (only if matches found)
            if yara_detections:
                logger.info(f"YARA detections for {payload.device_id}: {len(yara_detections)} rule(s) matched")
                for yara_det in yara_detections:
                    logger.info(f"  - {yara_det['rule']}: {yara_det['description']} (severity: {yara_det['severity']})")
            else:
                logger.debug(f"YARA scan complete for {payload.device_id}: No matches")
            
        except Exception as e:
            logger.error(f"Forensics analysis failed: {e}")
            # Ensure yara_detections is still empty list on error
            yara_detections = []
    
    # STEP 7: ENHANCED ML ANALYSIS
    enhanced_ml_result = enhanced_ml_engine.predict_anomaly(
        payload.model_dump(), 
        forensics_score=forensics_score
    )
    anomaly_score = enhanced_ml_result.get('anomaly_score', 0.0)
    
    # STEP 8: BASELINE PROFILE UPDATE & DEVIATION
    deviation_score = 0.0
    try:
        if not hasattr(state, "device_profile"):
            state.device_profile = {}
        profile.update_profile(state, payload.device_id, payload.model_dump())
        deviation_score = float(profile.compute_deviation_score(state, payload.device_id, payload.model_dump()) or 0.0)
        
        # Update baseline in DB if enough samples
        update_device_baseline(db, payload.device_id)
    except Exception:
        deviation_score = 0.0
    
    # STEP 9: RISK COMPUTATION
    # Compute telemetry health from last_seen (real-time computation)
    from ..db_utils import compute_telemetry_health
    telemetry_health_score, telemetry_status = compute_telemetry_health(device.last_seen)
    
    risk = compute_risk(
        payload.model_dump(), 
        anomaly_score=anomaly_score,
        forensics_score=forensics_score,
        enhanced_ml_result=enhanced_ml_result,
        history=hist,
        telemetry_health_score=telemetry_health_score
    )
    
    # Apply CTI boost to risk score
    if cti_boost > 0:
        logger.info(f"Applying CTI boost: +{cti_boost} to risk score")
        risk["risk_score"] = min(100.0, risk["risk_score"] + cti_boost)
        risk["risk_level"] = score_to_level(risk["risk_score"])
        risk["cti_boost"] = cti_boost
    
    # Fuse deviation score
    try:
        fused = min(100.0, risk["risk_score"] + (deviation_score * 0.25))
        risk["risk_score"] = round(fused, 2)
        risk["risk_level"] = score_to_level(risk["risk_score"])
    except Exception:
        pass
    
    # Determine device status based on risk
    if risk["risk_level"] == "GREEN":
        device_status = "OK"
    elif risk["risk_level"] == "YELLOW":
        device_status = "WARNING"
    else:
        device_status = "UNDER_ATTACK"
    
    # Update device risk and status in DB
    update_device_risk(db, payload.device_id, risk["risk_score"], risk["risk_level"], device_status)
    
    # STEP 10: ALERT CREATION & RESPONSE
    create_alert_flag = False
    if reason:
        create_alert_flag = True
    if risk["risk_score"] >= 40:  # Changed from 70 to 40 to include observation
        create_alert_flag = True
    if recon_data and (recon_data.get('indicator_count', 0) > 0 or recon_data.get('recon_risk', 0) >= 20):
        create_alert_flag = True
    
    backup_info = None
    alert_id = None
    response_actions = None
    
    if create_alert_flag:
        # Determine detection type (include YARA if matched)
        detection_types = []
        if reason:
            detection_types.append("Rules")
        if anomaly_score > 0.5:
            detection_types.append("ML")
        if recon_data.get('indicator_count', 0) > 0:
            detection_types.append("Recon")
        if forensics_results:
            detection_types.append("Forensics")
        if yara_detections:
            detection_types.append("YARA")  # Explicit YARA detection type
        detection_type = "/".join(detection_types) if detection_types else "Threshold"
        
        # Determine response action
        if risk["risk_score"] >= 70:
            response_action = "ISOLATE"
        elif risk["risk_score"] >= 55:
            response_action = "OBSERVE"
        elif risk["risk_score"] >= 40:
            response_action = "AUTO_FIX"
        else:
            response_action = "NONE"
        
        # Build alert details (include YARA results)
        alert_details = {
            "payload": payload.model_dump(),
            "risk": risk,
            "deviation": deviation_score,
            "forensics": forensics_results,
            "yara_detections": yara_detections,  # Store YARA matches separately
            "enhanced_ml": enhanced_ml_result,
            "recon": recon_data if recon_data.get("indicator_count", 0) > 0 else None,
            "cti_threats": cti_threats if cti_threats else None,  # CTI threat intelligence
            "telemetry_health": {
                "score": telemetry_health_score,
                "status": telemetry_status
            }
        }
        
        # Build alert reason (include YARA if matched)
        alert_reason = reason or "Risk threshold exceeded"
        if yara_detections:
            yara_rules = [d['rule'] for d in yara_detections]
            alert_reason = f"{alert_reason} | YARA: {', '.join(yara_rules[:3])}"  # Show first 3 rules
        if cti_threats:
            cti_summary = f"{len(cti_threats)} CTI threat(s)"
            alert_reason = f"{alert_reason} | CTI: {cti_summary}"
        if recon_data and recon_data.get("indicator_count", 0) > 0:
            recon_text = "; ".join(recon_data.get("indicators", [])[:10])
            alert_reason = f"{alert_reason} | Recon: {recon_text}"
        
        # Create alert in DB
        alert = create_alert(
            db,
            device_id=payload.device_id,
            risk_score=risk["risk_score"],
            risk_level=risk["risk_level"],
            detection_type=detection_type,
            response_action=response_action,
            details=alert_details,
            reason=alert_reason,
            severity=max(severity, 3 if risk["risk_score"] >= 70 else 2)
        )
        alert_id = alert.id
        
        # Backup files if RED
        if risk["risk_level"] == "RED":
            backup_info = _simulate_backup(payload.device_id, payload)
        
        # Execute response actions
        try:
            from ..response import handle_risk_action
            
            # Build device dict for response module (backward compatibility)
            dev_dict = {
                "quarantined": bool(device.quarantined),
                "last_seen": device.last_seen.timestamp() if device.last_seen else 0,
                "last_risk": device.risk_score,
                "risk_level": device.risk_level,
                "status": device.status,
                "ip": device.ip_address
            }
            
            response_actions = handle_risk_action(
                payload.device_id, 
                dev_dict, 
                payload.model_dump(), 
                risk, 
                recon_data
            )
            
            # Update DB based on response actions
            if response_action == "ISOLATE":
                isolation_details = {
                    "timestamp": time.time(),
                    "reason": alert_reason,
                    "risk_score": risk["risk_score"],
                    "trigger_alert_id": alert_id,
                    "actions": response_actions.get("actions", [])
                }
                set_device_isolated(db, payload.device_id, isolation_details)
            elif response_action == "OBSERVE":
                observation_details = {
                    "start": time.time(),
                    "reason": alert_reason,
                    "limit_kbps": 100,
                    "allowed_outbound": [],
                    "monitoring_level": "Enhanced"
                }
                set_device_under_observation(db, payload.device_id, observation_details)
        except Exception as e:
            logger.error(f"Response action failed: {e}")
            response_actions = {"error": str(e)}
        
        # Also add to in-memory state for backward compatibility
        state.alerts.insert(0, {
            "id": str(alert_id),
            "device_id": payload.device_id,
            "reason": alert_reason,
            "severity": alert.severity,
            "payload": payload.model_dump(),
            "risk": risk,
            "ts": alert.timestamp.timestamp()
        })
        
        return {
            "status": "alert",
            "alert_id": alert_id,
            "reason": alert_reason,
            "risk": risk,
            "device_status": {
                "device_id": device.device_id,
                "status": device.status,
                "risk_score": device.risk_score,
                "risk_level": device.risk_level,
                "quarantined": bool(device.quarantined)
            },
            "backup": backup_info,
            "response": response_actions
        }
    
    # No alert - return OK
    return {
        "status": "ok",
        "risk": risk,
        "device_status": {
            "device_id": device.device_id,
            "status": device.status,
            "risk_score": device.risk_score,
            "risk_level": device.risk_level,
            "telemetry_health": {
                "score": telemetry_health_score,
                "status": telemetry_status
            }
        }
    }
