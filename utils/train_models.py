import os
import sys
import numpy as np
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Ensure the root directory is in the python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Ensure ml_models directory exists
ML_MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml_models")
os.makedirs(ML_MODELS_DIR, exist_ok=True)

# 1. EMAIL PHISHING PIPELINE
def train_email_model():
    print("\n--- Training Email Spam/Phishing Model ---")
    
    phishing_texts = [
        "Urgent: Verify your online banking credentials immediately to avoid lock.",
        "Congratulations! You won a $1000 cash gift card. Click this link to redeem.",
        "Security Alert: Unusual login attempt detected on your bank profile. Verify here.",
        "Action Required: Update your billing credentials on our secure page.",
        "Dear customer, your credit card account has been frozen. Click here to confirm.",
        "IRS refund notification: Claim your tax return of $500 today by visiting this page.",
        "Your password expires in 2 hours. Go to our portal to reset it.",
        "Access warning: Someone accessed your account from a new browser. Verify profile.",
        "Free cash loans up to $5000! Apply now with no credit checks.",
        "Confirm your subscription update immediately to avoid cancellation."
    ] * 20 # 200 records

    safe_texts = [
        "Let's schedule our weekly sync meeting for tomorrow morning at 10 AM.",
        "Good morning, please find attached the draft compliance review document.",
        "Hey! Are we still meeting for lunch at the office cafeteria today?",
        "Please review the code changes in the FastAPI routers pull request.",
        "The server migration is completed successfully. Thank you for your support.",
        "Here are the notes from yesterday's database architecture workshop.",
        "Can you send me the documentation for the Naive Bayes TF-IDF module?",
        "Don't forget to submit your weekly timesheets before Friday afternoon.",
        "Hey, check out this beautiful dark mode CSS design I built for the UI.",
        "Attached is the project implementation plan report for your review."
    ] * 20 # 200 records

    texts = phishing_texts + safe_texts
    labels = [1] * len(phishing_texts) + [0] * len(safe_texts) # 1 = Phishing, 0 = Safe/Normal

    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)

    vectorizer = TfidfVectorizer(stop_words='english', max_features=500)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    model = MultinomialNB()
    model.fit(X_train_vec, y_train)

    preds = model.predict(X_test_vec)
    acc = accuracy_score(y_test, preds)
    print(f"Email Classifier Trained. Validation Accuracy: {acc * 100:.2f}%")

    joblib.dump(model, os.path.join(ML_MODELS_DIR, "phishing_model.pkl"))
    joblib.dump(vectorizer, os.path.join(ML_MODELS_DIR, "vectorizer.pkl"))
    print("Email model and vectorizer saved.")


# 2. URL DETECTOR PIPELINE
def train_url_model():
    print("\n--- Training URL Classifier Model ---")
    
    # URL Features scheme: [length, dots, specials, is_ip, is_https, is_shortened, keywords_count, subdomains, entropy]
    data = []
    
    # Safe URLs (200 records)
    for _ in range(200):
        length = np.random.randint(15, 45)
        dots = np.random.randint(1, 3)
        specials = np.random.randint(0, 3)
        is_ip = 0
        is_https = 1
        is_shortened = 0
        keywords_count = 0
        subdomains = np.random.randint(0, 2)
        entropy = np.random.uniform(2.5, 4.0)
        data.append([length, dots, specials, is_ip, is_https, is_shortened, keywords_count, subdomains, entropy, 0])

    # Malicious URLs (200 records)
    for _ in range(200):
        length = np.random.randint(55, 120)
        dots = np.random.randint(3, 7)
        specials = np.random.randint(4, 12)
        is_ip = np.random.choice([0, 1], p=[0.75, 0.25])
        is_https = np.random.choice([0, 1], p=[0.7, 0.3])
        is_shortened = np.random.choice([0, 1], p=[0.8, 0.2])
        keywords_count = np.random.randint(1, 4)
        subdomains = np.random.randint(2, 5)
        entropy = np.random.uniform(4.2, 5.8)
        data.append([length, dots, specials, is_ip, is_https, is_shortened, keywords_count, subdomains, entropy, 1])

    df = pd.DataFrame(data)
    X = df.drop(9, axis=1).values
    y = df[9].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=30, random_state=42)
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"URL Classifier Trained. Validation Accuracy: {acc * 100:.2f}%")

    joblib.dump(model, os.path.join(ML_MODELS_DIR, "url_model.pkl"))
    print("URL model saved.")


# 3. NETWORK IDS PACKET PIPELINE
def train_ids_model():
    print("\n--- Training Network IDS Model ---")
    
    # 9 features: [duration, protocol, service, src_bytes, dst_bytes, count, serror_rate, failed_logins, same_srv_rate]
    # Labels mapping: 0 = normal, 1 = DoS, 2 = Probe, 3 = R2L, 4 = U2R
    data = []

    # 1. Normal packet traffic (150 records)
    for _ in range(150):
        feat = [
            np.random.uniform(0.0, 1.2),  # duration
            np.random.choice([0, 1]),     # tcp/udp
            np.random.choice([0, 1]),     # http/smtp
            np.random.randint(100, 3000), # src_bytes
            np.random.randint(100, 6000), # dst_bytes
            np.random.randint(1, 8),      # count
            0.0,                          # serror_rate
            0,                            # num_failed_logins
            1.0                           # same_srv_rate
        ]
        data.append(feat + [0])

    # 2. DoS Syn Flood (50 records)
    for _ in range(50):
        feat = [
            0.0,                          # duration
            0,                            # tcp
            3,                            # private
            0,                            # src_bytes
            0,                            # dst_bytes
            np.random.randint(100, 400),  # count (flooding)
            1.0,                          # serror_rate (1.0 = SYN error)
            0,                            # num_failed_logins
            0.0                           # same_srv_rate
        ]
        data.append(feat + [1])

    # 3. Port Probe scanning (50 records)
    for _ in range(50):
        feat = [
            np.random.uniform(0.2, 5.0),
            0,
            4,                            # other
            0, 0,
            np.random.randint(40, 120),   # count
            0.0,
            0,
            0.1                           # low service rate
        ]
        data.append(feat + [2])

    # 4. R2L Brute-force Login Attempts (50 records)
    for _ in range(50):
        feat = [
            np.random.uniform(2.0, 15.0),
            0,
            0,                            # http
            np.random.randint(200, 800),
            np.random.randint(200, 800),
            1,
            0.0,
            np.random.randint(4, 12),     # failed logins
            1.0
        ]
        data.append(feat + [3])

    df = pd.DataFrame(data)
    X = df.drop(9, axis=1).values
    y = df[9].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=30, random_state=42)
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"Network IDS Model Trained. Validation Accuracy: {acc * 100:.2f}%")

    joblib.dump(model, os.path.join(ML_MODELS_DIR, "ids_model.pkl"))
    print("Network IDS model saved.")


if __name__ == "__main__":
    train_email_model()
    train_url_model()
    train_ids_model()
    print("\n--- Model Compilation Completed successfully ---")
