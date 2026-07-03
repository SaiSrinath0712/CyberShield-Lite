import json
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from jose import jwt

from backend import models, schemas
from backend.database import get_db
from backend.config import settings
from backend.services.ml_service import ml_service
from backend.services.rules import detect_sqli, detect_xss, scan_website

router = APIRouter(prefix="/api/predict", tags=["Security Threat Scanners"])

# Optional auth dependency header
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

def get_current_user_optional(token: Optional[str] = Depends(api_key_header), db: Session = Depends(get_db)) -> Optional[models.User]:
    if not token or not token.startswith("Bearer "):
        return None
    try:
        jwt_token = token.split(" ")[1]
        payload = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload.get("sub")
        return db.query(models.User).filter(models.User.username == username).first()
    except Exception:
        return None

def log_prediction_and_alert(
    db: Session,
    threat_type: str,
    input_data: str,
    prediction_output: str,
    confidence_score: float,
    explanation_dict: dict,
    is_malicious: bool,
    user: Optional[models.User],
    ip_address: str
):
    # Serialized explanation for database
    exp_json = json.dumps(explanation_dict)
    
    # 1. Create Prediction Log
    log_entry = models.PredictionLog(
        threat_type=threat_type,
        input_data=input_data,
        prediction_output=prediction_output,
        confidence_score=confidence_score,
        explanation=exp_json,
        is_malicious=is_malicious,
        source_ip=ip_address,
        user_id=user.id if user else None
    )
    db.add(log_entry)

    # 2. Create Alert entry if classified as malicious
    if is_malicious:
        # Determine risk level
        risk_level = explanation_dict.get("risk_level", "Medium")
        reasons = explanation_dict.get("reasons", ["Malicious behavior signature flagged."])
        
        alert_entry = models.Alert(
            threat_type=threat_type,
            source_ip=ip_address,
            payload=input_data[:200] + ("..." if len(input_data) > 200 else ""),
            risk_level=risk_level,
            explanation=", ".join(reasons)
        )
        db.add(alert_entry)
        
    db.commit()

# --- ENDPOINTS ---

@router.post("/phishing", response_model=schemas.PhishingEmailResponse)
def check_phishing_email(
    payload: schemas.PhishingEmailRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user_optional)
):
    ip_address = request.client.host if request.client else "127.0.0.1"
    
    # Classify email text
    result = ml_service.predict_phishing_email(payload.email_text)
    
    # Log in database
    log_prediction_and_alert(
        db=db,
        threat_type="Phishing Email",
        input_data=payload.email_text,
        prediction_output=result["prediction"],
        confidence_score=result["explanation"]["confidence"],
        explanation_dict=result["explanation"],
        is_malicious=result["is_phishing"],
        user=user,
        ip_address=ip_address
    )
    
    return result

@router.post("/sms", response_model=schemas.PhishingSMSResponse)
def check_phishing_sms(
    payload: schemas.PhishingSMSRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user_optional)
):
    ip_address = request.client.host if request.client else "127.0.0.1"
    
    # Classify SMS text
    result = ml_service.predict_phishing_sms(payload.sms_text)
    
    # Log in database
    log_prediction_and_alert(
        db=db,
        threat_type="Phishing SMS",
        input_data=payload.sms_text,
        prediction_output=result["prediction"],
        confidence_score=result["explanation"]["confidence"],
        explanation_dict=result["explanation"],
        is_malicious=result["is_phishing"],
        user=user,
        ip_address=ip_address
    )
    
    return result

@router.post("/url", response_model=schemas.URLResponse)
def check_url(
    payload: schemas.URLRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user_optional)
):
    ip_address = request.client.host if request.client else "127.0.0.1"
    
    # Classify URL structure
    result = ml_service.predict_url(payload.url)
    
    # Log in database
    log_prediction_and_alert(
        db=db,
        threat_type="Malicious URL",
        input_data=payload.url,
        prediction_output=result["prediction"],
        confidence_score=result["explanation"]["confidence"],
        explanation_dict=result["explanation"],
        is_malicious=result["is_malicious"],
        user=user,
        ip_address=ip_address
    )
    
    return result

@router.post("/website", response_model=schemas.WebsiteResponse)
def check_website(
    payload: schemas.WebsiteRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user_optional)
):
    ip_address = request.client.host if request.client else "127.0.0.1"
    
    # Analyze website features
    result = scan_website(payload.url)
    is_malicious = result["risk_level"] in ["High", "Critical"]
    
    # Standardize explanations for prediction logs
    explanation_dict = {
        "confidence": result["risk_score"],
        "risk_level": result["risk_level"],
        "reasons": result["checks_failed"] if result["checks_failed"] else ["All base security parameters passed."],
        "suggestions": result["recommendations"],
        "features_triggered": {
            "checks_passed_count": len(result["checks_passed"]),
            "checks_failed_count": len(result["checks_failed"])
        }
    }
    
    # Log in database
    log_prediction_and_alert(
        db=db,
        threat_type="Website Scan",
        input_data=payload.url,
        prediction_output=result["risk_level"],
        confidence_score=result["risk_score"],
        explanation_dict=explanation_dict,
        is_malicious=is_malicious,
        user=user,
        ip_address=ip_address
    )
    
    return result

@router.post("/ids", response_model=schemas.IDSResponse)
def check_network_packet(
    payload: schemas.IDSRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user_optional)
):
    ip_address = request.client.host if request.client else "127.0.0.1"
    
    # Convert incoming schema variables to dict representation for service
    packet_dict = payload.dict()
    
    # Classify packet
    result = ml_service.predict_ids(packet_dict)
    
    # Log in database
    log_prediction_and_alert(
        db=db,
        threat_type="Network IDS",
        input_data=f"Proto: {payload.protocol_type}, Service: {payload.service}, SrcBytes: {payload.src_bytes}",
        prediction_output=result["prediction"],
        confidence_score=result["explanation"]["confidence"],
        explanation_dict=result["explanation"],
        is_malicious=result["is_attack"],
        user=user,
        ip_address=ip_address
    )
    
    return result

@router.post("/sql", response_model=schemas.SQLResponse)
def check_sql_injection(
    payload: schemas.SQLRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user_optional)
):
    ip_address = request.client.host if request.client else "127.0.0.1"
    
    # Run SQL detector rules
    result = detect_sqli(payload.query_text)
    
    # Log in database
    log_prediction_and_alert(
        db=db,
        threat_type="SQLi Injection",
        input_data=payload.query_text,
        prediction_output=result["prediction"],
        confidence_score=result["explanation"]["confidence"],
        explanation_dict=result["explanation"],
        is_malicious=result["is_injection"],
        user=user,
        ip_address=ip_address
    )
    
    return result

@router.post("/xss", response_model=schemas.XSSResponse)
def check_xss_injection(
    payload: schemas.XSSRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[models.User] = Depends(get_current_user_optional)
):
    ip_address = request.client.host if request.client else "127.0.0.1"
    
    # Run XSS detector rules
    result = detect_xss(payload.payload_text)
    
    # Log in database
    log_prediction_and_alert(
        db=db,
        threat_type="XSS Injection",
        input_data=payload.payload_text,
        prediction_output=result["prediction"],
        confidence_score=result["explanation"]["confidence"],
        explanation_dict=result["explanation"],
        is_malicious=result["is_xss"],
        user=user,
        ip_address=ip_address
    )
    
    return result
