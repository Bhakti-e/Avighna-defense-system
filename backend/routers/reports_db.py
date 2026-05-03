# backend/routers/reports_db.py
"""
Reports router with DATABASE integration
"""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from .. import state
from ..database import get_db
from ..db_utils import create_report_record
from ..core.pdf_reports import generate_isolation_report
from .. import models
import os

router = APIRouter()


@router.get("/download/{filename}")
def download_pdf_report(filename: str):
    """Download PDF report by filename - for QR code scanning"""
    import os
    from pathlib import Path
    
    # Security: only allow PDF files from reports/pdf directory
    if not filename.endswith('.pdf'):
        raise HTTPException(400, "Invalid file type")
    
    # Remove any path traversal attempts
    filename = os.path.basename(filename)
    
    pdf_path = os.path.join("reports", "pdf", filename)
    
    if not os.path.exists(pdf_path):
        raise HTTPException(404, f"Report not found: {filename}")
    
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=filename,
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Cache-Control": "no-cache"
        }
    )


@router.get("/forensics/{alert_id}")
def get_forensics(alert_id: str, db: Session = Depends(get_db)):
    """Get forensics data for an alert"""
    # Try to find alert in DB
    try:
        alert_id_int = int(alert_id)
        alert = db.query(models.Alert).filter(models.Alert.id == alert_id_int).first()
        if alert and alert.details_json and "forensics" in alert.details_json:
            return alert.details_json["forensics"]
    except:
        pass
    
    # Fallback to file-based forensics
    path = f"reports/forensics_{alert_id}.json"
    if not os.path.exists(path):
        raise HTTPException(404, "forensics not found")
    return FileResponse(path, media_type="application/json", filename=os.path.basename(path))


@router.get("/incidents")
def list_incidents(db: Session = Depends(get_db)):
    """List forensics incidents from DATABASE"""
    # Get alerts with forensics data
    alerts = db.query(models.Alert).filter(
        models.Alert.details_json.isnot(None)
    ).order_by(models.Alert.timestamp.desc()).limit(100).all()
    
    incidents = []
    for alert in alerts:
        if alert.details_json and ("forensics" in alert.details_json or "recon" in alert.details_json):
            incidents.append({
                "incident_id": str(alert.id),
                "device_id": alert.device_id,
                "timestamp": alert.timestamp.isoformat(),
                "risk_score": alert.risk_score,
                "detection_type": alert.detection_type
            })
    
    return {"count": len(incidents), "incidents": incidents}


@router.get("/pdf/{alert_id}")
def get_pdf_report(alert_id: str, db: Session = Depends(get_db)):
    """Generate and return a natural language PDF report for an incident"""
    # TODO: Implement incident PDF generation
    raise HTTPException(501, "Incident PDF generation not yet implemented")



@router.get("/pdf/isolation/{device_id}")
def get_isolation_pdf_report(device_id: str, db: Session = Depends(get_db)):
    """Generate and return a comprehensive PDF report for an isolated device"""
    try:
        from ..pdf_reports import NaturalLanguagePDFGenerator
        
        # Check if device exists and is quarantined
        device = db.query(models.Device).filter(models.Device.device_id == device_id).first()
        if not device:
            raise HTTPException(404, f"Device {device_id} not found")
        
        if not device.quarantined:
            raise HTTPException(400, f"Device {device_id} is not isolated")
        
        # Check if report already exists
        existing_report = db.query(models.Report).filter(
            models.Report.device_id == device_id,
            models.Report.report_type == "ISOLATION"
        ).order_by(models.Report.created_at.desc()).first()
        
        if existing_report and os.path.exists(existing_report.file_path):
            return FileResponse(
                existing_report.file_path,
                media_type="application/pdf",
                filename=f"isolation_report_{device_id}.pdf"
            )
        
        # Generate PDF
        generator = NaturalLanguagePDFGenerator()
        pdf_path = generator.generate_isolation_report_with_state(device_id, state)
        
        if not os.path.exists(pdf_path):
            raise HTTPException(500, "Failed to generate isolation PDF report")
        
        # Store report record in DB
        create_report_record(
            db,
            device_id=device_id,
            report_type="ISOLATION",
            file_path=pdf_path
        )
        
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=f"isolation_report_{device_id}.pdf"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Error generating isolation PDF report: {str(e)}")


@router.get("/isolation/details")
def get_isolation_details(db: Session = Depends(get_db)):
    """Get detailed information about all isolated devices from DATABASE"""
    isolated_devices = db.query(models.Device).filter(
        models.Device.quarantined == 1
    ).order_by(models.Device.quarantine_time.desc()).all()
    
    isolation_list = []
    for device in isolated_devices:
        isolation_info = {
            "device_id": device.device_id,
            "status": device.status,
            "quarantine_time": device.quarantine_time.timestamp() if device.quarantine_time else None,
            "last_risk": device.risk_score,
            "risk_level": device.risk_level,
            "last_alert_id": device.alerts[0].id if device.alerts else None,
            "isolation_details": device.isolation_details or {},
            "backup_location": f"backups/{device.device_id}/",
            "forensics_available": bool(device.isolation_details and device.isolation_details.get("forensics_collected"))
        }
        
        # Add human-readable timestamp
        if device.quarantine_time:
            from datetime import datetime
            isolation_info["isolation_time_readable"] = device.quarantine_time.strftime("%B %d, %Y at %I:%M %p")
        
        isolation_list.append(isolation_info)
    
    return {
        "count": len(isolation_list),
        "isolated_devices": isolation_list
    }


@router.get("/observation/details")
def get_observation_details(db: Session = Depends(get_db)):
    """Get detailed information about all devices under observation from DATABASE"""
    observed_devices = db.query(models.Device).filter(
        models.Device.status == "UNDER_OBSERVATION"
    ).all()
    
    observation_list = []
    for device in observed_devices:
        obs_details = device.observation_details or {}
        observation_info = {
            "device_id": device.device_id,
            "status": device.status,
            "observation_start": obs_details.get("start"),
            "observation_reason": obs_details.get("reason"),
            "restrictions": obs_details,
            "last_risk": device.risk_score,
            "risk_level": device.risk_level
        }
        
        # Add human-readable timestamp
        if obs_details.get("start"):
            from datetime import datetime
            observation_info["observation_start_readable"] = datetime.fromtimestamp(obs_details["start"]).strftime("%B %d, %Y at %I:%M %p")
        
        observation_list.append(observation_info)
    
    return {
        "count": len(observation_list),
        "observed_devices": observation_list
    }
