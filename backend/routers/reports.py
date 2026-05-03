"""
Reports router for forensic report generation and management
"""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from ..database import get_db
from .. import models
from ..core.pdf_reports import generate_isolation_report
import os
from datetime import datetime

router = APIRouter()


class GenerateReportRequest(BaseModel):
    device_mac: str


@router.get("/list")
def list_reports(db: Session = Depends(get_db)):
    """List all generated forensic reports"""
    reports = db.query(models.Report).order_by(
        models.Report.created_at.desc()
    ).all()
    
    report_list = []
    for report in reports:
        # Get device info
        device = db.query(models.Device).filter(
            models.Device.device_id == report.device_id
        ).first()
        
        report_list.append({
            "id": report.id,
            "device_mac": report.device_id,
            "device_ip": device.ip_address if device else "Unknown",
            "risk_score": device.risk_score if device else 0,
            "threat_type": report.report_type,
            "generated_at": report.created_at.isoformat(),
            "filename": os.path.basename(report.file_path) if report.file_path else f"report_{report.id}.pdf"
        })
    
    return {"reports": report_list}


@router.post("/generate")
def generate_report(request: GenerateReportRequest, db: Session = Depends(get_db)):
    """Generate a forensic report for a device"""
    device_mac = request.device_mac
    
    # Find device
    device = db.query(models.Device).filter(
        models.Device.device_id == device_mac
    ).first()
    
    if not device:
        raise HTTPException(404, f"Device {device_mac} not found")
    
    # Check if device has any alerts or is isolated
    if not device.quarantined and device.risk_score < 50:
        raise HTTPException(400, "Device has no significant threats to report")
    
    # Generate PDF report
    try:
        pdf_path = generate_isolation_report(device_mac, db)
        
        # Create report record
        report = models.Report(
            device_id=device_mac,
            report_type="ISOLATION" if device.quarantined else "THREAT_ANALYSIS",
            file_path=pdf_path,
            created_at=datetime.utcnow()
        )
        db.add(report)
        db.commit()
        
        return {
            "success": True,
            "report_id": report.id,
            "filename": os.path.basename(pdf_path)
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to generate report: {str(e)}")


@router.get("/download/{report_id}")
def download_report(report_id: int, db: Session = Depends(get_db)):
    """Download a generated report"""
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    
    if not report:
        raise HTTPException(404, "Report not found")
    
    if not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(404, "Report file not found")
    
    filename = os.path.basename(report.file_path)
    
    return FileResponse(
        report.file_path,
        media_type="application/pdf",
        filename=filename,
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )
