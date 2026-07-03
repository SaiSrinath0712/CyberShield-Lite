import datetime
from sqlalchemy import Column, Integer, String, Float, Text, Boolean, DateTime
from backend.database import Base

class PredictionHistory(Base):
    __tablename__ = "prediction_history"

    id = Column(Integer, primary_key=True, index=True)
    threat_type = Column(String(50), nullable=False)  # Email, URL, File, Intrusion, SQLi, XSS, Login
    input_payload = Column(Text, nullable=False)
    prediction_verdict = Column(String(50), nullable=False)  # Safe, Suspicious, Dangerous
    confidence_score = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)  # Low, Medium, High, Critical
    explanation = Column(Text, nullable=False)  # JSON-encoded details
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class AlertLog(Base):
    __tablename__ = "alert_logs"

    id = Column(Integer, primary_key=True, index=True)
    threat_type = Column(String(50), nullable=False)
    risk_level = Column(String(20), nullable=False)
    description = Column(Text, nullable=False)
    payload_sample = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
