# backend/routers/alerts_db.py
"""
Alerts router with DATABASE integration
"""
from fastapi import APIRouter, Query, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from ..db_utils import get_recent_alerts

router = APIRouter()


@router.get("/")
def list_alerts(
    limit: int = Query(100, ge=1, le=1000),
    device_id: str = Query(None, description="Filter by device_id"),
    db: Session = Depends(get_db)
):
    """
    Return recent alerts from DATABASE
    """
    alerts = get_recent_alerts(db, limit=limit, device_id=device_id)
    
    alert_list = []
    for alert in alerts:
        alert_list.append({
            "id": str(alert.id),
            "device_id": alert.device_id,
            "timestamp": alert.timestamp.isoformat(),
            "risk_score": alert.risk_score,
            "risk_level": alert.risk_level,
            "detection_type": alert.detection_type,
            "response_action": alert.response_action,
            "reason": alert.reason,
            "severity": alert.severity,
            "details": alert.details_json,
            "ts": alert.timestamp.timestamp()
        })
    
    return {
        "count": len(alert_list), 
        "alerts": alert_list
    }
