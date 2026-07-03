import datetime
import json
from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend import models, schemas, auth
from backend.database import get_db

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard Operations"])

@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Computes real-time telemetry stats and chart data from the database.
    """
    total_scans = db.query(models.PredictionLog).count()
    total_threats = db.query(models.PredictionLog).filter(models.PredictionLog.is_malicious == True).count()
    
    # Calculate percentages
    threat_ratio = round((total_threats / total_scans * 100), 2) if total_scans > 0 else 0.0
    
    # Threat distribution by type
    distribution_query = db.query(
        models.PredictionLog.threat_type,
        func.count(models.PredictionLog.id)
    ).filter(models.PredictionLog.is_malicious == True).group_by(models.PredictionLog.threat_type).all()
    
    threat_distribution = {threat_type: count for threat_type, count in distribution_query}
    
    # Fill in defaults if empty
    default_types = ["Phishing Email", "Phishing SMS", "Malicious URL", "Website Scan", "Network IDS", "SQLi Injection", "XSS Injection"]
    for t in default_types:
        if t not in threat_distribution:
            threat_distribution[t] = 0

    # Today's scan and threats
    today_start = datetime.datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_scans = db.query(models.PredictionLog).filter(models.PredictionLog.created_at >= today_start).count()
    today_threats = db.query(models.PredictionLog).filter(
        models.PredictionLog.created_at >= today_start,
        models.PredictionLog.is_malicious == True
    ).count()

    # Recent Alerts (last 10 alerts)
    recent_alerts = db.query(models.Alert).order_by(models.Alert.created_at.desc()).limit(10).all()
    
    # Recent Logs (last 10 scans)
    recent_logs = db.query(models.PredictionLog).order_by(models.PredictionLog.created_at.desc()).limit(10).all()

    # Threat Timeline (last 7 days scans/threats)
    timeline_days = []
    timeline_scans = []
    timeline_threats = []
    
    for i in range(6, -1, -1):
        day = datetime.datetime.utcnow().date() - datetime.timedelta(days=i)
        day_start = datetime.datetime.combine(day, datetime.time.min)
        day_end = datetime.datetime.combine(day, datetime.time.max)
        
        scans_count = db.query(models.PredictionLog).filter(
            models.PredictionLog.created_at >= day_start,
            models.PredictionLog.created_at <= day_end
        ).count()
        
        threats_count = db.query(models.PredictionLog).filter(
            models.PredictionLog.created_at >= day_start,
            models.PredictionLog.created_at <= day_end,
            models.PredictionLog.is_malicious == True
        ).count()
        
        timeline_days.append(day.strftime("%b %d"))
        timeline_scans.append(scans_count)
        timeline_threats.append(threats_count)

    # Active Threats
    active_threats_count = db.query(models.Alert).filter(models.Alert.is_resolved == False).count()

    return {
        "total_scans": total_scans,
        "total_threats": total_threats,
        "threat_ratio": threat_ratio,
        "today_scans": today_scans,
        "today_threats": today_threats,
        "active_threats_count": active_threats_count,
        "threat_distribution": threat_distribution,
        "timeline": {
            "labels": timeline_days,
            "scans": timeline_scans,
            "threats": timeline_threats
        },
        "recent_alerts": [
            {
                "id": a.id,
                "threat_type": a.threat_type,
                "source_ip": a.source_ip,
                "payload": a.payload,
                "risk_level": a.risk_level,
                "explanation": a.explanation,
                "is_resolved": a.is_resolved,
                "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S")
            } for a in recent_alerts
        ],
        "recent_logs": [
            {
                "id": log.id,
                "threat_type": log.threat_type,
                "prediction_output": log.prediction_output,
                "confidence_score": log.confidence_score,
                "is_malicious": log.is_malicious,
                "source_ip": log.source_ip,
                "created_at": log.created_at.strftime("%Y-%m-%d %H:%M:%S")
            } for log in recent_logs
        ]
    }

@router.get("/history", response_model=List[schemas.PredictionLogOut])
def get_scan_history(
    threat_type: Optional[str] = None,
    is_malicious: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """
    Retrieves full transaction logs. Admins can view all, users can view their own.
    """
    query = db.query(models.PredictionLog)
    
    # Filter by user if not admin
    if current_user.role.lower() != "admin":
        query = query.filter(models.PredictionLog.user_id == current_user.id)
        
    if threat_type:
        query = query.filter(models.PredictionLog.threat_type == threat_type)
    if is_malicious is not None:
        query = query.filter(models.PredictionLog.is_malicious == is_malicious)
        
    return query.order_by(models.PredictionLog.created_at.desc()).all()

@router.get("/alerts", response_model=List[schemas.AlertOut])
def get_alerts(
    resolved: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """
    Retrieves all network alerts. Requires authenticated user.
    """
    query = db.query(models.Alert)
    if resolved is not None:
        query = query.filter(models.Alert.is_resolved == resolved)
    return query.order_by(models.Alert.created_at.desc()).all()

@router.post("/alerts/{alert_id}/resolve")
def resolve_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_admin_user)
):
    """
    Marks an alert as resolved. Requires Admin privileges.
    """
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    alert.is_resolved = True
    db.commit()
    return {"message": f"Alert {alert_id} resolved successfully."}

@router.get("/reports", response_model=List[schemas.SecurityReportOut])
def get_security_reports(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """
    Retrieves all generated security summary reports.
    """
    return db.query(models.SecurityReport).order_by(models.SecurityReport.created_at.desc()).all()

@router.post("/reports/generate", response_model=schemas.SecurityReportOut)
def generate_security_report(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """
    Compiles database statistics and saves a new security summary report.
    """
    total_scans = db.query(models.PredictionLog).count()
    total_threats = db.query(models.PredictionLog).filter(models.PredictionLog.is_malicious == True).count()
    
    distribution_query = db.query(
        models.PredictionLog.threat_type,
        func.count(models.PredictionLog.id)
    ).filter(models.PredictionLog.is_malicious == True).group_by(models.PredictionLog.threat_type).all()
    
    threat_distribution = {threat_type: count for threat_type, count in distribution_query}
    
    report_title = f"CyberShield Security Analysis Report - {datetime.datetime.utcnow().strftime('%B %d, %Y')}"
    
    new_report = models.SecurityReport(
        title=report_title,
        generated_by=current_user.username,
        total_scans=total_scans,
        total_threats=total_threats,
        threats_by_type=json.dumps(threat_distribution)
    )
    db.add(new_report)
    db.commit()
    db.refresh(new_report)
    return new_report

@router.get("/training-runs", response_model=List[schemas.TrainingRunOut])
def get_training_runs(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    """
    Lists ML model training runs from the real-time database.
    """
    return db.query(models.TrainingRun).order_by(models.TrainingRun.trained_at.desc()).all()
