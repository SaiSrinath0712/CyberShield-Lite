import os
import sys
import numpy as np
import pandas as pd

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT_DIR)

DATASETS_DIR = os.path.join(ROOT_DIR, "datasets")
os.makedirs(DATASETS_DIR, exist_ok=True)

# 1. Export Phishing Dataset
from utils.train_models import train_email_model, extract_url_features_vector

print("[1/3] Extracting Phishing Email & SMS Dataset...")
# We inspect the code or re-run the dataset creation logic
import re

with open(os.path.join(ROOT_DIR, "utils", "train_models.py"), "r", encoding="utf-8") as f:
    content = f.read()

# Extract phishing_samples
phish_match = re.search(r"phishing_samples = \[(.*?)\]\s+safe_samples = \[(.*?)\]", content, re.DOTALL)
if phish_match:
    phish_code = phish_match.group(1)
    safe_code = phish_match.group(2)
    phishing_samples = [s.strip().strip('"').strip("'") for s in phish_code.split('",') if s.strip() and not s.strip().startswith('#')]
    # Clean up multiline/comments
    phishing_cleaned = []
    for line in phish_code.splitlines():
        line = line.strip()
        if line.startswith('"') and line.endswith('",'):
            phishing_cleaned.append(line[1:-2])
        elif line.startswith('"') and line.endswith('"'):
            phishing_cleaned.append(line[1:-1])

    safe_cleaned = []
    for line in safe_code.splitlines():
        line = line.strip()
        if line.startswith('"') and line.endswith('",'):
            safe_cleaned.append(line[1:-2])
        elif line.startswith('"') and line.endswith('"'):
            safe_cleaned.append(line[1:-1])

    # Augment exact variants matching train_models.py
    phish_rows = []
    for s in phishing_cleaned:
        phish_rows.append({"text": s, "label": "phishing", "is_phishing": 1})
        phish_rows.append({"text": f"ATTENTION: {s}", "label": "phishing", "is_phishing": 1})
        phish_rows.append({"text": f"CRITICAL SECURITY ALERT: {s}", "label": "phishing", "is_phishing": 1})
        phish_rows.append({"text": f"[Urgent Notification] {s}", "label": "phishing", "is_phishing": 1})
        phish_rows.append({"text": f"{s} Please respond within 12 hours.", "label": "phishing", "is_phishing": 1})
        phish_rows.append({"text": f"Action Required: {s}", "label": "phishing", "is_phishing": 1})

    safe_rows = []
    for s in safe_cleaned:
        safe_rows.append({"text": s, "label": "safe", "is_phishing": 0})
        safe_rows.append({"text": f"Hi team, {s}", "label": "safe", "is_phishing": 0})
        safe_rows.append({"text": f"Update: {s}", "label": "safe", "is_phishing": 0})
        safe_rows.append({"text": f"FYI: {s}", "label": "safe", "is_phishing": 0})
        safe_rows.append({"text": f"Good morning! {s} Thanks.", "label": "safe", "is_phishing": 0})
        safe_rows.append({"text": f"Meeting notes: {s}", "label": "safe", "is_phishing": 0})

    df_phish = pd.DataFrame(phish_rows + safe_rows)
    phish_path = os.path.join(DATASETS_DIR, "phishing_dataset.csv")
    df_phish.to_csv(phish_path, index=False, encoding="utf-8")
    print(f" -> Saved {len(df_phish)} samples to {phish_path}")

# 2. Export URL Dataset
print("[2/3] Extracting Malicious URL Dataset...")
url_match = re.search(r"legitimate_urls = \[(.*?)\]\s+malicious_urls = \[(.*?)\]", content, re.DOTALL)
if url_match:
    legit_code = url_match.group(1)
    mal_code = url_match.group(2)
    legit_urls = [line.strip()[1:-2] if line.strip().endswith('",') else line.strip()[1:-1] for line in legit_code.splitlines() if line.strip().startswith('"')]
    mal_urls = [line.strip()[1:-2] if line.strip().endswith('",') else line.strip()[1:-1] for line in mal_code.splitlines() if line.strip().startswith('"')]

    paths_safe = ["/home", "/about-us", "/products", "/contact", "/docs/api", "/pricing", "/features", "/terms", "/blog/news", "/dashboard"]
    queries_safe = ["?ref=nav", "?lang=en", "?page=2", "?sort=newest", "?filter=all"]

    expanded_safe_urls = []
    for u in legit_urls:
        expanded_safe_urls.append(u)
        for p in paths_safe[:3]:
            expanded_safe_urls.append(u.rstrip("/") + p)
        for q in queries_safe[:2]:
            expanded_safe_urls.append(u + q)

    phish_tokens = ["?id=49281&sec=1", "?token=9382f1b0a", "/verify.php", "/account/login", "/confirm-identity", "/update-billing"]
    expanded_phish_urls = []
    for u in mal_urls:
        expanded_phish_urls.append(u)
        for tok in phish_tokens[:4]:
            expanded_phish_urls.append(u.rstrip("/") + tok)

    url_rows = []
    for u in expanded_safe_urls:
        feat = extract_url_features_vector(u)
        url_rows.append({
            "url": u,
            "label": "safe",
            "is_malicious": 0,
            "url_length": feat[0],
            "num_dots": feat[1],
            "has_ip": feat[2],
            "has_at_symbol": feat[3],
            "is_https": feat[4],
            "num_hyphens": feat[5],
            "num_subdirs": feat[6],
            "has_suspicious_tld": feat[7],
            "has_phishing_keywords": feat[8]
        })

    for u in expanded_phish_urls:
        feat = extract_url_features_vector(u)
        url_rows.append({
            "url": u,
            "label": "malicious",
            "is_malicious": 1,
            "url_length": feat[0],
            "num_dots": feat[1],
            "has_ip": feat[2],
            "has_at_symbol": feat[3],
            "is_https": feat[4],
            "num_hyphens": feat[5],
            "num_subdirs": feat[6],
            "has_suspicious_tld": feat[7],
            "has_phishing_keywords": feat[8]
        })

    df_urls = pd.DataFrame(url_rows)
    url_path = os.path.join(DATASETS_DIR, "url_dataset.csv")
    df_urls.to_csv(url_path, index=False, encoding="utf-8")
    print(f" -> Saved {len(df_urls)} samples to {url_path}")

# 3. Export Network IDS Dataset
print("[3/3] Generating Network IDS Dataset...")
np.random.seed(42)
data = []
# 0: Normal (500)
for _ in range(500):
    duration = int(np.random.exponential(scale=2.0))
    protocol = np.random.choice([0, 1, 2], p=[0.75, 0.20, 0.05])
    service = np.random.choice([0, 1, 2, 3, 4, 5], p=[0.50, 0.20, 0.10, 0.10, 0.05, 0.05])
    src_bytes = int(np.random.normal(loc=450, scale=120))
    dst_bytes = int(np.random.normal(loc=3500, scale=800))
    count = int(np.random.poisson(lam=4))
    serror_rate = round(float(np.random.uniform(0.0, 0.05)), 2)
    failed_logins = 0
    same_srv_rate = round(float(np.random.uniform(0.90, 1.0)), 2)
    data.append([duration, protocol, service, max(src_bytes, 10), max(dst_bytes, 10), max(count, 1), serror_rate, failed_logins, same_srv_rate, 0, "Normal"])

# 1: DoS (400)
for _ in range(400):
    duration = 0
    protocol = np.random.choice([0, 1, 2], p=[0.7, 0.1, 0.2])
    service = np.random.choice([0, 1, 3], p=[0.6, 0.2, 0.2])
    src_bytes = int(np.random.normal(loc=1200, scale=300))
    dst_bytes = 0
    count = int(np.random.randint(180, 512))
    serror_rate = round(float(np.random.uniform(0.85, 1.0)), 2)
    failed_logins = 0
    same_srv_rate = round(float(np.random.uniform(0.80, 1.0)), 2)
    data.append([duration, protocol, service, max(src_bytes, 50), dst_bytes, count, serror_rate, failed_logins, same_srv_rate, 1, "DoS"])

# 2: Probe (250)
for _ in range(250):
    duration = int(np.random.randint(0, 3))
    protocol = np.random.choice([0, 1, 2], p=[0.4, 0.3, 0.3])
    service = np.random.choice([0, 1, 2, 3, 4, 5, 6, 7], p=[0.15, 0.15, 0.15, 0.15, 0.1, 0.1, 0.1, 0.1])
    src_bytes = int(np.random.randint(0, 150))
    dst_bytes = int(np.random.randint(0, 80))
    count = int(np.random.randint(40, 220))
    serror_rate = round(float(np.random.uniform(0.40, 0.95)), 2)
    failed_logins = 0
    same_srv_rate = round(float(np.random.uniform(0.05, 0.40)), 2)
    data.append([duration, protocol, service, src_bytes, dst_bytes, count, serror_rate, failed_logins, same_srv_rate, 2, "Probe"])

# 3: R2L (150)
for _ in range(150):
    duration = int(np.random.exponential(scale=15.0))
    protocol = 0
    service = np.random.choice([1, 2, 3], p=[0.4, 0.4, 0.2])
    src_bytes = int(np.random.normal(loc=300, scale=100))
    dst_bytes = int(np.random.normal(loc=800, scale=250))
    count = int(np.random.randint(1, 10))
    serror_rate = 0.0
    failed_logins = int(np.random.randint(3, 9))
    same_srv_rate = round(float(np.random.uniform(0.70, 1.0)), 2)
    data.append([duration, protocol, service, max(src_bytes, 20), max(dst_bytes, 20), count, serror_rate, failed_logins, same_srv_rate, 3, "R2L"])

# 4: U2R (100)
for _ in range(100):
    duration = int(np.random.exponential(scale=25.0))
    protocol = 0
    service = np.random.choice([2, 3], p=[0.6, 0.4])
    src_bytes = int(np.random.normal(loc=2500, scale=500))
    dst_bytes = int(np.random.normal(loc=4000, scale=900))
    count = 1
    serror_rate = 0.0
    failed_logins = 0
    same_srv_rate = 1.0
    data.append([duration, protocol, service, max(src_bytes, 100), max(dst_bytes, 100), count, serror_rate, failed_logins, same_srv_rate, 4, "U2R"])

columns = ["duration", "protocol_type", "service", "src_bytes", "dst_bytes", "count", "serror_rate", "failed_logins", "same_srv_rate", "attack_class_id", "attack_class_name"]
df_ids = pd.DataFrame(data, columns=columns)
ids_path = os.path.join(DATASETS_DIR, "ids_dataset.csv")
df_ids.to_csv(ids_path, index=False, encoding="utf-8")
print(f" -> Saved {len(df_ids)} samples to {ids_path}")

print("\nAll datasets successfully exported to the 'datasets/' folder!")
