"""
CyberShield AI Lite - Scripts Train Models Runner
Synchronized with utils/train_models.py for real-time model retraining and telemetry logging.
"""
from utils.train_models import (
    train_email_model as train_phishing_email_model,
    train_url_model,
    train_ids_model
)

if __name__ == "__main__":
    print("===================================================================")
    print("  CYBERSHIELD AI - RETRAINING ALL ML MODELS WITH REAL-TIME DATA    ")
    print("===================================================================")
    train_phishing_email_model()
    train_url_model()
    train_ids_model()
    print("\n[OK] Retraining successfully completed across all threat models.")
