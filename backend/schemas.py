from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import datetime

# --- COMMON EXPLANATION SCHEMA ---
class XAIExplanation(BaseModel):
    verdict: str  # Safe, Suspicious, Dangerous
    threat_type: str
    confidence: float
    risk_level: str  # Low, Medium, High, Critical
    reasons: List[str]
    suggestions: List[str]
    features_triggered: Optional[Dict[str, Any]] = None

# --- REQUEST & RESPONSE SCHEMAS ---

# Email
class EmailScanRequest(BaseModel):
    subject: str = Field(default="", description="Email subject line")
    body: str = Field(..., description="Email body content")

class EmailScanResponse(BaseModel):
    verdict: str
    is_phishing: bool
    explanation: XAIExplanation

# URL
class URLScanRequest(BaseModel):
    url: str = Field(..., description="Website target URL")

class URLScanResponse(BaseModel):
    verdict: str
    is_malicious: bool
    explanation: XAIExplanation

# File extension scanner
class FileScanRequest(BaseModel):
    filename: str = Field(..., description="File name")
    extension: str = Field(..., description="File extension with or without dot")

class FileScanResponse(BaseModel):
    verdict: str
    is_unsafe: bool
    explanation: XAIExplanation

# Network IDS packet scanner
class IntrusionScanRequest(BaseModel):
    duration: float = Field(default=0.0)
    protocol_type: str = Field(default="tcp")  # tcp, udp, icmp
    service: str = Field(default="http")
    flag: str = Field(default="SF")
    src_bytes: int = Field(default=0)
    dst_bytes: int = Field(default=0)
    count: int = Field(default=1)
    serror_rate: float = Field(default=0.0)
    num_failed_logins: int = Field(default=0)

class IntrusionScanResponse(BaseModel):
    verdict: str
    is_attack: bool
    attack_type: str
    explanation: XAIExplanation

# SQL injection detector
class SQLScanRequest(BaseModel):
    query_text: str = Field(..., description="Payload text")

class SQLScanResponse(BaseModel):
    verdict: str
    is_injection: bool
    explanation: XAIExplanation

# XSS detector
class XSSScanRequest(BaseModel):
    payload_text: str = Field(..., description="Payload script/HTML markup")

class XSSScanResponse(BaseModel):
    verdict: str
    is_xss: bool
    explanation: XAIExplanation

# Login brute force monitor
class LoginScanRequest(BaseModel):
    username: str = Field(..., description="User attempting login")
    ip_address: str = Field(..., description="IP of the login client")
    failed_logins_count: int = Field(..., description="Consecutive failed attempts in history window")
    time_window_seconds: int = Field(default=60, description="Timeframe of login requests")

class LoginScanResponse(BaseModel):
    verdict: str
    is_brute_force: bool
    explanation: XAIExplanation


# --- OUTPUT HISTORY & DASHBOARD SCHEMAS ---

class PredictionHistoryOut(BaseModel):
    id: int
    threat_type: str
    input_payload: str
    prediction_verdict: str
    confidence_score: float
    risk_level: str
    explanation: str
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class AlertLogOut(BaseModel):
    id: int
    threat_type: str
    risk_level: str
    description: str
    payload_sample: str
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class DashboardStats(BaseModel):
    total_scans: int
    total_threats: int
    phishing_emails: int
    spam_emails: int
    blocked_urls: int
    network_attacks: int
    recent_alerts: List[AlertLogOut]
    distribution: Dict[str, int]
