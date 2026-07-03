import os
import sys
import datetime
import numpy as np
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# Ensure the parent directory is in the python path for backend imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import SessionLocal, engine, Base
from backend.models import TrainingRun

# Ensure models directory exists
MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend", "models")
os.makedirs(MODELS_DIR, exist_ok=True)

# Helper to log runs in database
def log_training_run_to_db(model_name: str, size: int, acc: float, prec: float, rec: float, f1: float, status: str, notes: str = ""):
    session = SessionLocal()
    try:
        run = TrainingRun(
            model_name=model_name,
            trained_at=datetime.datetime.utcnow(),
            accuracy=acc,
            precision=prec,
            recall=rec,
            f1_score=f1,
            dataset_size=size,
            status=status,
            notes=notes
        )
        session.add(run)
        session.commit()
        print(f"[Database Log] Successfully logged training run for {model_name} in database.")
    except Exception as e:
        session.rollback()
        print(f"[Database Error] Could not write training log to database: {e}")
    finally:
        session.close()


# =====================================================================
# 1. TRAIN PHISHING EMAIL DETECTOR
# =====================================================================
def train_phishing_email_model():
    print("\n--- Training Phishing Email Model ---")
    
    # 1. Generate High-Quality Representative Dataset
    phishing_templates = [
        "Urgent: Verify your banking credentials immediately or face account suspension.",
        "Congratulations! You won a $1000 Amazon gift card. Click here to claim your reward.",
        "Security Alert: Unusual login detected on your PayPal account. Please confirm your identity.",
        "Action Required: Update your social security details on our secure portal.",
        "Your password expires in 24 hours. Click this link to reset it now.",
        "Dear customer, your credit card has been locked. Verify details to unlock.",
        "IRS Notice: You have an outstanding tax refund. Claim it now by clicking here.",
        "Unauthorized access detected on your system. Log in here to secure your profile.",
        "Free cash loan approved! No credit check required. Click to apply.",
        "Dear user, confirm your subscription details to avoid interruption."
    ] * 25  # 250 records

    safe_templates = [
        "Project status update: Let's schedule our weekly sync meeting for tomorrow.",
        "Hi, are we still on for lunch at 1:00 PM today?",
        "Attached is the code review request for the new authentication router.",
        "Please find the invoice for the cloud hosting services attached.",
        "Good morning, here is the summary of yesterday's conference call.",
        "The team achieved the quarterly sales target. Congratulations everyone!",
        "Draft implementation plan for CyberShield AI has been uploaded to the repository.",
        "Reminder: Complete your annual compliance training by Friday afternoon.",
        "Can you send me the documentation on the Naive Bayes vectorizer pipeline?",
        "Hey! Just checking in on how your engineering portfolio project is going."
    ] * 25  # 250 records

    texts = phishing_templates + safe_templates
    labels = [1] * len(phishing_templates) + [0] * len(safe_templates)  # 1 = Phishing, 0 = Safe
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)
    
    # TF-IDF vectorization
    vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    # Train Multinomial Naive Bayes classifier
    model = MultinomialNB()
    model.fit(X_train_vec, y_train)
    
    # Predict & Evaluate
    preds = model.predict(X_test_vec)
    acc = accuracy_score(y_test, preds)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, preds, average='binary')
    
    print(f"Accuracy: {acc:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f} | F1 Score: {f1:.4f}")
    
    # Save model and vectorizer
    joblib.dump(model, os.path.join(MODELS_DIR, "phishing_model.pkl"))
    joblib.dump(vectorizer, os.path.join(MODELS_DIR, "vectorizer.pkl"))
    print("Email Phishing Model and Vectorizer saved.")
    
    # Log to DB
    log_training_run_to_db(
        model_name="Phishing Email",
        size=len(texts),
        acc=float(acc),
        prec=float(prec),
        rec=float(rec),
        f1=float(f1),
        status="Completed",
        notes="Trained using TF-IDF + Multinomial Naive Bayes. Representational dataset size 500."
    )


# =====================================================================
# 2. TRAIN PHISHING URL DETECTOR
# =====================================================================
def train_url_model():
    print("\n--- Training Phishing URL Model ---")
    
    # 1. Generate High-Quality Synthetic URL Dataset
    # Features scheme: [length, dots, specials, is_ip, is_https, is_shortened, keywords_count, subdomains, entropy]
    
    data = []
    # Safe URLs (200 records)
    for _ in range(200):
        length = np.random.randint(15, 45)
        dots = np.random.randint(1, 3)
        specials = np.random.randint(0, 3)
        is_ip = 0
        is_https = 1  # 95% of safe sites have HTTPS
        is_shortened = 0
        keywords_count = 0
        subdomains = np.random.randint(0, 2)
        entropy = np.random.uniform(2.5, 4.0)
        data.append([length, dots, specials, is_ip, is_https, is_shortened, keywords_count, subdomains, entropy, 0])

    # Phishing/Malicious URLs (200 records)
    for _ in range(200):
        length = np.random.randint(55, 120)
        dots = np.random.randint(3, 7)
        specials = np.random.randint(4, 12)
        is_ip = np.random.choice([0, 1], p=[0.75, 0.25])
        is_https = np.random.choice([0, 1], p=[0.7, 0.3])  # Phishing often lacks HTTPS
        is_shortened = np.random.choice([0, 1], p=[0.8, 0.2])
        keywords_count = np.random.randint(1, 4)
        subdomains = np.random.randint(2, 5)
        entropy = np.random.uniform(4.2, 5.8)
        data.append([length, dots, specials, is_ip, is_https, is_shortened, keywords_count, subdomains, entropy, 1])

    df = pd.DataFrame(data, columns=[
        "length", "dots", "specials", "is_ip", "is_https", 
        "is_shortened", "keywords_count", "subdomains", "entropy", "label"
    ])
    
    X = df.drop("label", axis=1).values
    y = df["label"].values
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train Random Forest Classifier
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, preds, average='binary')
    
    print(f"Accuracy: {acc:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f} | F1 Score: {f1:.4f}")
    
    # Save Model
    joblib.dump(model, os.path.join(MODELS_DIR, "url_model.pkl"))
    print("URL Classification Model saved.")
    
    # Log to DB
    log_training_run_to_db(
        model_name="URL Classifier",
        size=len(data),
        acc=float(acc),
        prec=float(prec),
        rec=float(rec),
        f1=float(f1),
        status="Completed",
        notes="Trained using Random Forest (50 trees). Feature vector size 9."
    )


# =====================================================================
# 3. TRAIN INTRUSION DETECTION SYSTEM (IDS)
# =====================================================================
def train_ids_model():
    print("\n--- Training Network IDS Model ---")
    
    # Network Packet features vector length 36
    # Label mapping:
    # 0 = Normal, 1 = DoS, 2 = Probe, 3 = R2L, 4 = U2R, 5 = DDoS, 6 = Brute Force, 7 = Bot Attack
    attack_classes = ["normal", "DoS", "Probe", "R2L", "U2R", "DDoS", "Brute Force", "Bot Attack"]
    
    data = []
    
    # Helper to generate feature vectors
    # features: [duration, protocol, service, flag, src_bytes, dst_bytes, land, wrong_frag, urgent, hot, num_failed_logins, logged_in, num_compromised, root_shell, su_attempted, num_root, file_creations, num_shells, num_access_files, count, srv_count, serror, rerror, same_srv, diff_srv, srv_diff_host, dst_host_count, dst_host_srv_count, dst_host_same_srv, dst_host_diff_srv, dst_host_same_src_port, dst_host_srv_diff_host, dst_host_serror, dst_host_srv_serror, dst_host_rerror, dst_host_srv_rerror]
    
    # Generate 150 normal records
    for _ in range(150):
        feat = [
            np.random.uniform(0.0, 1.5),  # duration
            np.random.choice([0, 1, 2]),  # protocol
            np.random.choice([0, 1, 5]),  # service
            0,  # flag (SF)
            np.random.randint(100, 5000),  # src_bytes
            np.random.randint(100, 10000),  # dst_bytes
            0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,  # land through access_files
            np.random.randint(1, 10),  # count
            np.random.randint(1, 10),  # srv_count
            0.0, 0.0, 1.0, 0.0, 0.0,  # serror, rerror, same_srv, diff_srv, srv_diff_host
            np.random.randint(1, 50), np.random.randint(1, 50), 1.0, 0.0, 0.05, 0.0, 0.0, 0.0, 0.0, 0.0  # dst host stats
        ]
        data.append(feat + [0]) # label normal (0)
        
    # Generate 50 DoS flood records
    for _ in range(50):
        feat = [
            0.0,  # duration
            0,  # protocol tcp
            3,  # service private
            1,  # flag S0 (SYN error)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # land through access_files
            np.random.randint(100, 500),  # high connection count
            np.random.randint(100, 500),
            1.0, 0.0, 0.08, 0.07, 0.0,  # serror_rate=1.0
            255, np.random.randint(1, 10), 0.03, 0.07, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0  # serror dst stats
        ]
        data.append(feat + [1]) # DoS (1)
        
    # Generate 50 Probe/Scan records
    for _ in range(50):
        feat = [
            np.random.uniform(0.1, 10.0),
            0,
            4, # service other
            2, # flag REJ (Rejected)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            np.random.randint(50, 150),
            1,
            0.0, 1.0, 0.05, 0.9, 0.0,  # high rerror_rate (1.0)
            255, 1, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 1.0, 1.0
        ]
        data.append(feat + [2]) # Probe (2)

    # Generate 50 Brute Force records
    for _ in range(50):
        feat = [
            np.random.uniform(2.0, 25.0),
            0,
            0, # http/ssh
            0, # SF
            np.random.randint(200, 1000),
            np.random.randint(200, 1000),
            0, 0, 0, 0,
            np.random.randint(5, 15),  # high failed logins
            0, 0, 0, 0, 0, 0, 0, 0,
            1, 1, 0.0, 0.0, 1.0, 0.0, 0.0,
            np.random.randint(1, 5), np.random.randint(1, 5), 1.0, 0.0, 0.2, 0.0, 0.0, 0.0, 0.0, 0.0
        ]
        data.append(feat + [6]) # Brute Force (6)
        
    # Convert to DataFrame
    df = pd.DataFrame(data)
    X = df.drop(36, axis=1).values
    y = df[36].values
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train Random Forest Classifier
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, preds, average='macro')
    
    print(f"Accuracy: {acc:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f} | F1 Score: {f1:.4f}")
    
    # Save raw model
    joblib.dump(model, os.path.join(MODELS_DIR, "ids_model.pkl"))
    print("Network IDS Classifier Model saved.")
    
    # Log to DB
    log_training_run_to_db(
        model_name="Network IDS",
        size=len(data),
        acc=float(acc),
        prec=float(prec),
        rec=float(rec),
        f1=float(f1),
        status="Completed",
        notes="Trained using Random Forest. Covers Normal, DoS, Probe, and Brute Force attacks."
    )


# =====================================================================
# MAIN RUNNER
# =====================================================================
if __name__ == "__main__":
    print("Initialising database tables...")
    Base.metadata.create_all(bind=engine)
    
    print("Starting Machine Learning Model Training Pipelines...")
    train_phishing_email_model()
    train_url_model()
    train_ids_model()
    print("\n--- All Model Trainings Completed Successfully! ---")
