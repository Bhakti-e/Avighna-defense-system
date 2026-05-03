"""
Statistics API Router
Provides aggregated stats for dashboard
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..database import get_db
from .. import models, state
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/dashboard")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Get aggregated statistics for main dashboard
    Single unified device count from device manager
    """
    try:
        from ..device_manager import device_manager
        
        # Get device counts - only ACTIVE and RECENTLY_SEEN devices
        total_devices = device_manager.get_device_count()  # ACTIVE + RECENTLY_SEEN
        active_devices = device_manager.get_device_count(status="ACTIVE")
        
        # Get isolated and observed counts
        isolated_devices = db.query(models.Device).filter(
            models.Device.quarantined == 1
        ).count()
        observed_devices = db.query(models.Device).filter(
            models.Device.status == "UNDER_OBSERVATION"
        ).count()
        
        # Get alert count
        total_alerts = db.query(models.Alert).count()
        recent_alerts = db.query(models.Alert).filter(
            models.Alert.severity >= 3
        ).count()
        
        # Get reconnaissance events from state (not in DB)
        recon_events = len(state.reconnaissance_findings) if hasattr(state, 'reconnaissance_findings') else 0
        
        # Calculate threat score
        threat_score = 0
        if isolated_devices > 0:
            threat_score = 95
        elif recent_alerts > 5:
            threat_score = 75
        elif recon_events > 5:
            threat_score = 65
        elif observed_devices > 0:
            threat_score = 45
        else:
            threat_score = 25
        
        return {
            "devices": {
                "total": total_devices,
                "active": active_devices,
                "isolated": isolated_devices,
                "observed": observed_devices,
                "normal": total_devices - isolated_devices - observed_devices
            },
            "alerts": {
                "total": total_alerts,
                "recent": recent_alerts,
                "critical": db.query(models.Alert).filter(models.Alert.severity >= 4).count()
            },
            "reconnaissance": {
                "events": recon_events,
                "active": recon_events > 0
            },
            "threat_score": threat_score,
            "status": "critical" if threat_score >= 70 else "warning" if threat_score >= 40 else "normal"
        }
    except Exception as e:
        logger.error(f"Failed to get dashboard stats: {e}")
        return {
            "devices": {"total": 0, "active": 0, "isolated": 0, "observed": 0, "normal": 0},
            "alerts": {"total": 0, "recent": 0, "critical": 0},
            "reconnaissance": {"events": 0, "active": False},
            "threat_score": 0,
            "status": "unknown",
            "error": str(e)
        }


@router.get("/network-activity")
def get_network_activity(hours: int = 24, db: Session = Depends(get_db)):
    """
    Get network activity statistics for the specified time period
    """
    try:
        # Get telemetry count
        telemetry_count = db.query(models.TelemetryHistory).count()
        
        # Get device activity
        active_devices = db.query(models.Device).filter(
            models.Device.last_seen.isnot(None)
        ).count()
        
        return {
            "telemetry_records": telemetry_count,
            "active_devices": active_devices,
            "time_period_hours": hours
        }
    except Exception as e:
        logger.error(f"Failed to get network activity: {e}")
        return {
            "telemetry_records": 0,
            "active_devices": 0,
            "time_period_hours": hours,
            "error": str(e)
        }


@router.get("/threat-trends")
def get_threat_trends(days: int = 7, db: Session = Depends(get_db)):
    """
    Get threat trends over time
    Returns daily counts of alerts by severity
    """
    try:
        # Get alerts grouped by day
        # This is a simplified version - you may want to add proper date grouping
        alerts = db.query(
            models.Alert.severity,
            func.count(models.Alert.id).label('count')
        ).group_by(models.Alert.severity).all()
        
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for alert in alerts:
            if alert.severity >= 4:
                severity_counts["critical"] += alert.count
            elif alert.severity == 3:
                severity_counts["high"] += alert.count
            elif alert.severity == 2:
                severity_counts["medium"] += alert.count
            else:
                severity_counts["low"] += alert.count
        
        return {
            "period_days": days,
            "severity_counts": severity_counts,
            "total_threats": sum(severity_counts.values())
        }
    except Exception as e:
        logger.error(f"Failed to get threat trends: {e}")
        return {
            "period_days": days,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "total_threats": 0,
            "error": str(e)
        }
