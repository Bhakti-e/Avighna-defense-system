"""
Database utility functions for DOME/AVIGHNA
Helper functions for common DB operations
"""
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
import time
from . import models


def get_or_create_device(db: Session, device_id: str, **kwargs) -> models.Device:
    """
    Get existing device or create new one
    Sets first_seen only on creation
    """
    device = db.query(models.Device).filter(models.Device.device_id == device_id).first()
    
    if not device:
        # Create new device
        now = datetime.utcnow()
        device = models.Device(
            device_id=device_id,
            first_seen=now,
            last_seen=now,
            **kwargs
        )
        db.add(device)
        db.commit()
        db.refresh(device)
    
    return device


def update_device_last_seen(db: Session, device_id: str) -> None:
    """
    Update last_seen timestamp for device
    Called on every successful telemetry ingest
    """
    device = db.query(models.Device).filter(models.Device.device_id == device_id).first()
    if device:
        now = datetime.utcnow()
        evaluate_device_visibility(db, device, now)  # Detect any gap before recovery.
        device.last_seen = now  # Legacy compatibility only.
        device.last_agent_heartbeat = now
        evaluate_device_visibility(db, device, now)
        db.commit()


def update_device_risk(db: Session, device_id: str, risk_score: float, risk_level: str, status: str) -> None:
    """
    Update device risk and status after risk computation
    """
    device = db.query(models.Device).filter(models.Device.device_id == device_id).first()
    if device:
        device.risk_score = risk_score
        device.risk_level = risk_level
        device.status = status
        device.last_seen = datetime.utcnow()
        db.commit()


def compute_telemetry_health(last_agent_heartbeat: datetime, now=None) -> tuple[Optional[float], str]:
    """
    Compute telemetry health only from the endpoint-agent heartbeat.
    Returns (score 0-100, status string)
    
    OPTION A: Compute at read-time (preferred - no fake data)
    """
    if not last_agent_heartbeat:
        return None, "UNKNOWN"
    now = now or datetime.utcnow()
    if now.tzinfo is not None:
        now = now.astimezone(timezone.utc).replace(tzinfo=None)
    if last_agent_heartbeat.tzinfo is not None:
        last_agent_heartbeat = last_agent_heartbeat.astimezone(timezone.utc).replace(tzinfo=None)
    time_since_last = (now - last_agent_heartbeat).total_seconds()
    if time_since_last < 0:
        return None, "UNKNOWN"  # Future observations need clock/source investigation.
    
    TELEMETRY_TIMEOUT = 60  # seconds - stale threshold
    TELEMETRY_LOST_TIMEOUT = 180  # seconds - lost threshold
    
    if time_since_last <= TELEMETRY_TIMEOUT:
        # Healthy - recent telemetry
        score = 100.0
        status = "ACTIVE"
    elif time_since_last <= TELEMETRY_LOST_TIMEOUT:
        # Stale - no recent telemetry but not lost
        # Linear decay from 100 to 20 over the stale window
        decay_window = TELEMETRY_LOST_TIMEOUT - TELEMETRY_TIMEOUT
        decay_amount = (time_since_last - TELEMETRY_TIMEOUT) / decay_window
        score = max(20.0, 100.0 - (80.0 * decay_amount))
        status = "STALE"
    else:
        # Lost - no telemetry for extended period
        score = 0.0
        status = "LOST"
    
    return score, status


def compute_baseline_profile(db: Session, device_id: str, min_samples: int = 20) -> Optional[Dict[str, Any]]:
    """
    Compute baseline profile from telemetry_history
    Returns None if insufficient samples
    
    NO FAKE DATA - only compute from real telemetry
    """
    # Get recent telemetry samples
    telemetry_records = db.query(models.TelemetryHistory).filter(
        models.TelemetryHistory.device_id == device_id
    ).order_by(models.TelemetryHistory.timestamp.desc()).limit(100).all()
    
    if len(telemetry_records) < min_samples:
        return None
    
    # Compute averages
    total_failed = sum(t.failed_logins for t in telemetry_records)
    total_conn = sum(t.connections_count for t in telemetry_records)
    total_bytes = sum(t.bytes_out for t in telemetry_records)
    count = len(telemetry_records)
    
    baseline = {
        "count": count,
        "avg_failed": total_failed / count,
        "avg_conn": total_conn / count,
        "avg_bytes": total_bytes / count,
        "computed_at": datetime.utcnow().isoformat()
    }
    
    return baseline


def update_device_baseline(db: Session, device_id: str) -> None:
    """
    Update device baseline profile if enough samples exist
    """
    baseline = compute_baseline_profile(db, device_id)
    if baseline:
        device = db.query(models.Device).filter(models.Device.device_id == device_id).first()
        if device:
            device.baseline_profile = baseline
            db.commit()


def create_alert(db: Session, device_id: str, risk_score: float, risk_level: str, 
                detection_type: str, response_action: str, details: Dict[str, Any],
                reason: str = None, severity: int = 1) -> models.Alert:
    """
    Create alert record from real detection event
    """
    alert = models.Alert(
        device_id=device_id,
        timestamp=datetime.utcnow(),
        risk_score=risk_score,
        risk_level=risk_level,
        detection_type=detection_type,
        response_action=response_action,
        details_json=details,
        reason=reason,
        severity=severity
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def create_telemetry_record(db: Session, device_id: str, payload: Dict[str, Any]) -> models.TelemetryHistory:
    """
    Store telemetry record for baseline computation
    """
    # Extract connections count (handle int or list)
    connections = payload.get("connections", 0)
    if isinstance(connections, list):
        connections_count = len(connections)
    elif isinstance(connections, dict):
        connections_count = sum(len(v) if hasattr(v, '__len__') else 1 for v in connections.values())
    else:
        connections_count = int(connections) if connections else 0
    
    telemetry = models.TelemetryHistory(
        device_id=device_id,
        timestamp=datetime.utcnow(),
        failed_logins=payload.get("failed_logins", 0),
        connections_count=connections_count,
        bytes_out=payload.get("bytes_out", 0),
        outbound_ips=payload.get("outbound_ips", []),
        suspicious_file=payload.get("suspicious_file"),
        recon_indicators=payload.get("recon_indicators"),
        raw_payload=payload
    )
    db.add(telemetry)
    device = db.query(models.Device).filter(models.Device.device_id == device_id).first()
    if device:
        device.last_endpoint_event = telemetry.timestamp
    db.commit()
    db.refresh(telemetry)
    return telemetry


def create_report_record(db: Session, device_id: str, report_type: str, 
                        file_path: str, alert_id: Optional[int] = None) -> models.Report:
    """
    Store report record after PDF generation
    """
    report = models.Report(
        device_id=device_id,
        alert_id=alert_id,
        report_type=report_type,
        file_path=file_path,
        created_at=datetime.utcnow()
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def get_recent_alerts(db: Session, limit: int = 100, device_id: Optional[str] = None) -> List[models.Alert]:
    """
    Get recent alerts, optionally filtered by device
    """
    query = db.query(models.Alert)
    
    if device_id:
        query = query.filter(models.Alert.device_id == device_id)
    
    return query.order_by(models.Alert.timestamp.desc()).limit(limit).all()


def get_all_devices(db: Session, include_network: bool = False) -> List[models.Device]:
    """
    Get all devices, optionally filtering out network-discovered ones
    """
    query = db.query(models.Device)
    
    if not include_network:
        # Exclude ARP/nmap discovered devices
        query = query.filter(~models.Device.source.in_(["arp", "nmap", "scanner"]))
    
    return query.order_by(models.Device.risk_score.desc()).all()


def set_device_isolated(db: Session, device_id: str, isolation_details: Dict[str, Any]) -> None:
    """
    Mark device as isolated with details
    """
    device = db.query(models.Device).filter(models.Device.device_id == device_id).first()
    if device:
        device.quarantined = 1
        device.quarantine_time = datetime.utcnow()
        device.isolation_details = isolation_details
        device.status = "ISOLATED"
        db.commit()


def set_device_under_observation(db: Session, device_id: str, observation_details: Dict[str, Any]) -> None:
    """
    Mark device as under observation with details
    """
    device = db.query(models.Device).filter(models.Device.device_id == device_id).first()
    if device:
        device.observation_details = observation_details
        device.status = "UNDER_OBSERVATION"
        db.commit()


def evaluate_device_visibility(db: Session, device: models.Device, now=None):
    """Persist one loss/recovery event per heartbeat episode; never assign threat risk."""
    from sqlalchemy.exc import IntegrityError
    now = now or datetime.utcnow()
    _, state = compute_telemetry_health(device.last_agent_heartbeat, now)
    previous = device.agent_health_state
    kind = None
    if state in {"STALE", "LOST"} and previous not in {"STALE", "LOST"}:
        kind = "visibility_lost"
    elif state == "ACTIVE" and previous in {"STALE", "LOST"}:
        kind = "visibility_recovered"
    if kind:
        key = f"{kind}|{device.device_id}|{device.last_agent_heartbeat.isoformat()}"
        if not db.query(models.Alert).filter(models.Alert.visibility_event_key == key).first():
            reason = ("Visibility lost / possible agent impairment. Cause unknown; "
                      "outage, misconfiguration, or tampering require investigation."
                      if kind == "visibility_lost" else
                      "Agent heartbeat resumed. Recovery does not establish device security.")
            event = models.Alert(
                device_id=device.device_id, timestamp=now, risk_score=0.0,
                risk_level="UNKNOWN", detection_type="SensorHealth", severity=1,
                response_action="NONE", reason=reason, visibility_event_key=key,
                details_json={
                    "kind": kind, "source": "agent-health", "rule": "heartbeat-gap-v1",
                    "observed_at": now.isoformat() + "Z",
                    "last_agent_heartbeat": device.last_agent_heartbeat.isoformat() + "Z",
                    "state": state, "stale_after_seconds": 60, "offline_after_seconds": 180,
                    "limitations": "Visibility only; not proof of compromise or recovery from compromise.",
                },
            )
            try:
                with db.begin_nested():
                    db.add(event)
                    db.flush()
            except IntegrityError:
                # The unique event key also deduplicates concurrent insert attempts.
                if not db.query(models.Alert).filter(models.Alert.visibility_event_key == key).first():
                    raise
    if state != "UNKNOWN":
        device.agent_health_state = state
    return state


def evaluate_visibility(db: Session, now=None):
    """Reconcile on inventory reads. No scanner or autonomous worker is started."""
    now = now or datetime.utcnow()
    for device in db.query(models.Device).all():
        evaluate_device_visibility(db, device, now)
    db.commit()
