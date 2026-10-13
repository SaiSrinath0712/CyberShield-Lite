import os
import json
import csv
import io
import random
import datetime
from fastapi import FastAPI, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from sqlalchemy.orm import Session
from typing import List, Optional

from backend.database import engine, Base, get_db
from backend import models, schemas
from backend.services.ml_service import ml_service
from backend.services.rule_service import scan_file_extension, scan_sql_injection, scan_xss, scan_html_injection, scan_unified_injection, scan_login_attempts

# Initialize Database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="CyberShield AI Lite",
    description="Intelligent Cybersecurity Scanners & Threat Dashboard",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper to write logs to DB
def log_scan_transaction(
    db: Session,
    threat_type: str,
    payload: str,
    verdict: str,
    confidence: float,
    risk_level: str,
    explanation_dict: dict
):
    exp_str = json.dumps(explanation_dict)
    
    # 1. Log transaction
    log_entry = models.PredictionHistory(
        threat_type=threat_type,
        input_payload=payload,
        prediction_verdict=verdict,
        confidence_score=confidence,
        risk_level=risk_level,
        explanation=exp_str
    )
    db.add(log_entry)
    
    # 2. Log Alert if unsafe
    if verdict != "Safe":
        alert_entry = models.AlertLog(
            threat_type=threat_type,
            risk_level=risk_level,
            description=", ".join(explanation_dict.get("reasons", ["Suspicious activity flagged."])),
            payload_sample=payload[:100] + ("..." if len(payload) > 100 else "")
        )
        db.add(alert_entry)
        
    db.commit()
    db.refresh(log_entry)
    return log_entry


# --- REST ENDPOINTS ---

@app.post("/predict/email", response_model=schemas.EmailScanResponse)
def check_email(payload: schemas.EmailScanRequest, db: Session = Depends(get_db)):
    result = ml_service.check_email(payload.subject, payload.body)
    
    log_scan_transaction(
        db=db,
        threat_type="Email Spam/Phishing",
        payload=f"Subj: {payload.subject} | Body: {payload.body}",
        verdict=result["verdict"],
        confidence=result["explanation"]["confidence"],
        risk_level=result["explanation"]["risk_level"],
        explanation_dict=result["explanation"]
    )
    return result

@app.post("/predict/url", response_model=schemas.URLScanResponse)
def check_url(payload: schemas.URLScanRequest, db: Session = Depends(get_db)):
    result = ml_service.check_url(payload.url)
    
    log_scan_transaction(
        db=db,
        threat_type="Malicious URL",
        payload=payload.url,
        verdict=result["verdict"],
        confidence=result["explanation"]["confidence"],
        risk_level=result["explanation"]["risk_level"],
        explanation_dict=result["explanation"]
    )
    return result

@app.post("/predict/file", response_model=schemas.FileScanResponse)
def check_file(payload: schemas.FileScanRequest, db: Session = Depends(get_db)):
    result = scan_file_extension(payload.filename, payload.extension)
    
    log_scan_transaction(
        db=db,
        threat_type="Suspicious File",
        payload=f"File: {payload.filename} (Ext: {payload.extension})",
        verdict=result["verdict"],
        confidence=result["explanation"]["confidence"],
        risk_level=result["explanation"]["risk_level"],
        explanation_dict=result["explanation"]
    )
    return result

@app.post("/predict/intrusion", response_model=schemas.IntrusionScanResponse)
def check_intrusion(payload: schemas.IntrusionScanRequest, db: Session = Depends(get_db)):
    packet_dict = payload.model_dump()
    result = ml_service.check_intrusion(packet_dict)
    
    log_scan_transaction(
        db=db,
        threat_type="Network IDS",
        payload=f"Proto: {payload.protocol_type}, Service: {payload.service}, SrcBytes: {payload.src_bytes}",
        verdict=result["verdict"],
        confidence=result["explanation"]["confidence"],
        risk_level=result["explanation"]["risk_level"],
        explanation_dict=result["explanation"]
    )
    return result

@app.post("/predict/sql", response_model=schemas.SQLScanResponse)
def check_sqli(payload: schemas.SQLScanRequest, db: Session = Depends(get_db)):
    result = scan_sql_injection(payload.query_text)
    
    log_scan_transaction(
        db=db,
        threat_type="SQLi Injection",
        payload=payload.query_text,
        verdict=result["verdict"],
        confidence=result["explanation"]["confidence"],
        risk_level=result["explanation"]["risk_level"],
        explanation_dict=result["explanation"]
    )
    return result

@app.post("/predict/xss", response_model=schemas.XSSScanResponse)
def check_xss(payload: schemas.XSSScanRequest, db: Session = Depends(get_db)):
    result = scan_xss(payload.payload_text)
    
    log_scan_transaction(
        db=db,
        threat_type="XSS Attack",
        payload=payload.payload_text,
        verdict=result["verdict"],
        confidence=result["explanation"]["confidence"],
        risk_level=result["explanation"]["risk_level"],
        explanation_dict=result["explanation"]
    )
    return result

@app.post("/predict/html", response_model=schemas.HTMLScanResponse)
def check_html(payload: schemas.HTMLScanRequest, db: Session = Depends(get_db)):
    result = scan_html_injection(payload.payload_text)
    
    log_scan_transaction(
        db=db,
        threat_type="HTML Injection",
        payload=payload.payload_text,
        verdict=result["verdict"],
        confidence=result["explanation"]["confidence"],
        risk_level=result["explanation"]["risk_level"],
        explanation_dict=result["explanation"]
    )
    return result

@app.post("/predict/injection", response_model=schemas.UnifiedInjectionScanResponse)
def check_unified_injection(payload: schemas.UnifiedInjectionScanRequest, db: Session = Depends(get_db)):
    result = scan_unified_injection(payload.payload_text)
    
    log_scan_transaction(
        db=db,
        threat_type="Injection Audit",
        payload=payload.payload_text,
        verdict=result["verdict"],
        confidence=result["explanation"]["confidence"],
        risk_level=result["explanation"]["risk_level"],
        explanation_dict=result["explanation"]
    )
    return result

@app.post("/predict/login", response_model=schemas.LoginScanResponse)
def check_login_brute_force(payload: schemas.LoginScanRequest, db: Session = Depends(get_db)):
    result = scan_login_attempts(payload.username, payload.ip_address, payload.failed_logins_count, payload.time_window_seconds)
    
    log_scan_transaction(
        db=db,
        threat_type="Login Monitor",
        payload=f"User: {payload.username} | IP: {payload.ip_address} | FailCount: {payload.failed_logins_count}",
        verdict=result["verdict"],
        confidence=result["explanation"]["confidence"],
        risk_level=result["explanation"]["risk_level"],
        explanation_dict=result["explanation"]
    )
    return result


@app.get("/telemetry/status")
def get_telemetry_status(db: Session = Depends(get_db)):
    """Returns real-time telemetry diagnostics and active model status."""
    total_scans = db.query(models.PredictionHistory).count()
    total_threats = db.query(models.PredictionHistory).filter(models.PredictionHistory.prediction_verdict != "Safe").count()
    return {
        "status": "online",
        "connection": "connected",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_scans": total_scans,
        "total_threats": total_threats,
        "active_scanners_count": 6,
        "models": {
            "phishing_nlp": "Operational (TF-IDF + MultinomialNB)",
            "url_classifier": "Operational (Random Forest 100 Trees)",
            "ids_classifier": "Operational (Random Forest 5 Classes)",
            "file_intelligence": "Operational (100+ Extension Registry & RTLO)",
            "injection_checker": "Operational (Multi-Vector SQLi + XSS + HTML)",
            "login_monitor": "Operational (Sliding Window Brute-Force Rate Limiter)"
        },
        "database": "Active (SQLite: cybershield_lite.db)",
        "server_env": "FastAPI Async Threat Gateway"
    }

@app.get("/telemetry/sample-packet")
def get_sample_telemetry_packet():
    """Generates a realistic live simulated telemetry network packet for instant IDS testing."""
    is_anomaly = random.random() < 0.4
    if is_anomaly:
        attack_kind = random.choice(["dos", "probe", "r2l"])
        if attack_kind == "dos":
            return {
                "duration": 0.0,
                "protocol_type": "tcp",
                "service": "private",
                "flag": "S0",
                "src_bytes": random.randint(1000, 1800),
                "dst_bytes": 0,
                "count": random.randint(220, 480),
                "serror_rate": round(random.uniform(0.85, 1.0), 2),
                "num_failed_logins": 0,
                "hint": "DoS SYN Flood Simulation"
            }
        elif attack_kind == "r2l":
            return {
                "duration": round(random.uniform(5.0, 25.0), 2),
                "protocol_type": "tcp",
                "service": "http",
                "flag": "SF",
                "src_bytes": random.randint(250, 450),
                "dst_bytes": random.randint(700, 1100),
                "count": random.randint(2, 8),
                "serror_rate": 0.0,
                "num_failed_logins": random.randint(3, 7),
                "hint": "Brute-force Remote-to-Local Simulation"
            }
        else:
            return {
                "duration": round(random.uniform(0.0, 2.0), 2),
                "protocol_type": random.choice(["tcp", "udp", "icmp"]),
                "service": random.choice(["other", "private", "smtp"]),
                "flag": "REJ",
                "src_bytes": random.randint(10, 80),
                "dst_bytes": random.randint(0, 40),
                "count": random.randint(50, 180),
                "serror_rate": round(random.uniform(0.4, 0.9), 2),
                "num_failed_logins": 0,
                "hint": "Port Scanning / Probe Simulation"
            }
    else:
        return {
            "duration": round(random.uniform(0.0, 1.5), 2),
            "protocol_type": random.choice(["tcp", "udp"]),
            "service": random.choice(["http", "smtp", "ftp"]),
            "flag": "SF",
            "src_bytes": random.randint(300, 1500),
            "dst_bytes": random.randint(2000, 5000),
            "count": random.randint(1, 8),
            "serror_rate": 0.0,
            "num_failed_logins": 0,
            "hint": "Standard Baseline Flow"
        }

@app.get("/dashboard", response_model=schemas.DashboardStats)
def get_dashboard_data(db: Session = Depends(get_db)):
    total_scans = db.query(models.PredictionHistory).count()
    total_threats = db.query(models.PredictionHistory).filter(models.PredictionHistory.prediction_verdict != "Safe").count()
    
    phishing_emails = db.query(models.PredictionHistory).filter(
        models.PredictionHistory.threat_type == "Email Spam/Phishing",
        models.PredictionHistory.prediction_verdict == "Dangerous"
    ).count()
    
    spam_emails = db.query(models.PredictionHistory).filter(
        models.PredictionHistory.threat_type == "Email Spam/Phishing",
        models.PredictionHistory.prediction_verdict == "Suspicious"
    ).count()
    
    blocked_urls = db.query(models.PredictionHistory).filter(
        models.PredictionHistory.threat_type == "Malicious URL",
        models.PredictionHistory.prediction_verdict != "Safe"
    ).count()
    
    network_attacks = db.query(models.PredictionHistory).filter(
        models.PredictionHistory.threat_type == "Network IDS",
        models.PredictionHistory.prediction_verdict != "Safe"
    ).count()

    # Get recent 10 alerts
    recent_alerts_models = db.query(models.AlertLog).order_by(models.AlertLog.created_at.desc()).limit(10).all()
    recent_alerts = [schemas.AlertLogOut.model_validate(a) for a in recent_alerts_models]

    dist_query = db.query(
        models.PredictionHistory.threat_type,
        func.count(models.PredictionHistory.id)
    ).filter(models.PredictionHistory.prediction_verdict != "Safe").group_by(models.PredictionHistory.threat_type).all()
    
    distribution = {threat_type: count for threat_type, count in dist_query}
    
    # Defaults
    all_modules = ["Email Spam/Phishing", "Malicious URL", "Suspicious File", "Network IDS", "SQLi Injection", "XSS Attack", "Login Monitor"]
    for m in all_modules:
        if m not in distribution:
            distribution[m] = 0

    return {
        "total_scans": total_scans,
        "total_threats": total_threats,
        "phishing_emails": phishing_emails,
        "spam_emails": spam_emails,
        "blocked_urls": blocked_urls,
        "network_attacks": network_attacks,
        "recent_alerts": recent_alerts,
        "distribution": distribution
    }


@app.get("/history", response_model=List[schemas.PredictionHistoryOut])
def get_prediction_history(
    query: Optional[str] = Query(None, description="Search payload or explanation"),
    threat_type: Optional[str] = Query(None, description="Filter by threat module type"),
    verdict: Optional[str] = Query(None, description="Filter by Safe, Suspicious, Dangerous"),
    db: Session = Depends(get_db)
):
    sql_query = db.query(models.PredictionHistory)
    
    if threat_type:
        sql_query = sql_query.filter(models.PredictionHistory.threat_type == threat_type)
    if verdict:
        sql_query = sql_query.filter(models.PredictionHistory.prediction_verdict == verdict)
    if query:
        sql_query = sql_query.filter(
            models.PredictionHistory.input_payload.like(f"%{query}%") |
            models.PredictionHistory.explanation.like(f"%{query}%")
        )
        
    return sql_query.order_by(models.PredictionHistory.created_at.desc()).all()


# --- DATABASE EXPORTS ---

@app.get("/history/export/csv")
def export_history_csv(db: Session = Depends(get_db)):
    """Exports prediction history database records as a CSV stream."""
    history = db.query(models.PredictionHistory).order_by(models.PredictionHistory.created_at.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(["ID", "Timestamp", "Threat Module", "Payload", "Verdict", "Confidence", "Risk Level"])
    
    for log in history:
        writer.writerow([
            log.id,
            log.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            log.threat_type,
            log.input_payload,
            log.prediction_verdict,
            f"{log.confidence_score}%",
            log.risk_level
        ])
        
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cybershield_threats_history.csv"}
    )

@app.get("/history/export/json")
def export_history_json(db: Session = Depends(get_db)):
    """Exports prediction history database records as a JSON stream."""
    history = db.query(models.PredictionHistory).order_by(models.PredictionHistory.created_at.desc()).all()
    
    data = []
    for log in history:
        data.append({
            "id": log.id,
            "timestamp": log.created_at.isoformat(),
            "threat_type": log.threat_type,
            "input_payload": log.input_payload,
            "verdict": log.prediction_verdict,
            "confidence": log.confidence_score,
            "risk_level": log.risk_level,
            "explanation": json.loads(log.explanation)
        })
        
    output = io.StringIO()
    json.dump(data, output, indent=2)
    output.seek(0)
    
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=cybershield_threats_history.json"}
    )


# --- SERVE FRONTEND STATIC FILES ---

frontend_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if not os.path.exists(frontend_path):
    os.makedirs(frontend_path, exist_ok=True)

# Mount files
app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
