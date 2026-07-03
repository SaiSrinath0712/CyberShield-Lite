# CyberShield AI

### Intelligent Intrusion Detection, Phishing Detection & Explainable Cyber Threat Analysis System

CyberShield AI is an industry-level, production-ready AI-powered cybersecurity platform that protects organizations by analyzing and explaining digital threats. It utilizes Machine Learning classifiers alongside rule-based heuristic parsing engines to flag, log, and diagnose security anomalies across multiple vectors. Every classification includes an **Explainable AI (XAI)** panel detailing which features triggered the rating and recommended response playbook countermeasures.

---

## 🚀 Key Modules & Capabilities

1. **Phishing Email Detection**: Semantic analysis using TF-IDF + Multinomial Naive Bayes to classify social engineering email content.
2. **SMS Phishing (Smishing) Detection**: Inspects short messages for prize scams, credential requests, and shortened links.
3. **Malicious URL Detection**: Random Forest Classifier evaluating structural features (length, dots, entropy, subdomains, HTTPS absence, IP usage).
4. **Website Vulnerability Analyzer**: Active scans checking for HTTPS, open redirects, missing CSP/HSTS security headers, and unsafe form behaviors.
5. **Network Intrusion Detection System (IDS)**: Random Forest Classifier trained on network connection metrics (duration, byte sizes, SYN/REJ errors) to detect DoS, Probe, and Brute Force attacks.
6. **SQL Injection (SQLi) Detector**: Heuristic grammar parser analyzing queries for tautology bypasses (`OR 1=1`), table drops, schema queries, and comment tricks.
7. **XSS Payload Detector**: Parses markup inputs for event handlers (`onload`, `onerror`), script triggers, and iframe injections.
8. **Real-Time Security Command Console**: Interlocks telemetry metrics, active alert tables, historical search feeds, and Chart.js timeline metrics.
9. **ML Performance Database**: Stores and monitors ML model training scores (Accuracy, F1-Score, precision) directly in the database.
10. **Role-Based JWT Auth**: Provides secure password hashing (bcrypt), token expiration, and administrative privilege boundaries.

---

## 🛠️ Technology Stack

- **Backend**: Python, FastAPI, Pydantic v2, SQLAlchemy ORM, SQLite/Postgres.
- **Frontend**: Vanilla HTML5, CSS3 (Premium dark-cyberpunk glassmorphism, responsive grids), ES6 Javascript, Chart.js.
- **Machine Learning**: Scikit-Learn, Pandas, NumPy, Joblib, TF-IDF.
- **Security**: JWT tokens, bcrypt cryptography, Rate-limiting headers.
- **Deployment**: Docker, Uvicorn server.

---

## 📂 Project Architecture & Directory Layout

```text
CyberShieldAI/
├── backend/
│   ├── models/            # Serialized ML model dumps (.pkl)
│   ├── routers/           # FastAPI router endpoints (auth, predict, dashboard)
│   ├── services/          # Core analysis logic (ml_service, rule_engines)
│   ├── auth.py            # JWT and bcrypt security helpers
│   ├── config.py          # Settings validation loader
│   ├── database.py        # SQLAlchemy connections
│   ├── main.py            # FastAPI main server entrypoint
│   ├── models.py          # DB Schemas (User, Alert, PredictionLog, TrainingRun)
│   └── schemas.py         # Pydantic input/output schemas
├── frontend/
│   ├── css/
│   │   └── style.css      # Custom glassmorphic styling
│   ├── js/
│   │   └── app.js         # API integration, Chart.js managers, tabs switcher
│   ├── index.html         # Gateway access portal (Login/Register)
│   └── dashboard.html     # Main analytics command console
├── scripts/
│   └── train_models.py    # Generates synthetic datasets, trains models, logs metrics in DB
├── Dockerfile             # Container configuration
├── requirements.txt       # Dependencies manifest
├── .env.example           # Configurations template
└── README.md              # Documentation
```

---

## ⚙️ Installation & Running Locally

### 1. Set Up Environment
```bash
# Clone the repository and navigate inside
cd CyberShieldAI

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Train Models & Initialize Databases
Run the model compiler script. This programmatically generates high-fidelity representational datasets, trains the machine learning classifiers, saves the serialized `.pkl` models to `backend/models/`, and records the training run accuracy in the SQLite database automatically.
```bash
python scripts/train_models.py
```

### 3. Run FastAPI Web Server
Start the development server:
```bash
uvicorn backend.main:app --reload
```
Open your web browser and navigate to:
**`http://127.0.0.1:8000`**

- The first user account created through the register portal is automatically granted **Admin** role privileges, which are required to mark active alerts as resolved.

---

## 🐳 Docker Deployment

To build and run the entire application container locally:
```bash
# Build the Docker Image
docker build -t cybershield-ai .

# Run the Container
docker run -p 8000:8000 cybershield-ai
```
Navigate to `http://localhost:8000` to access the application.

---

## 🛡️ Future Improvements & SaaS Scale
- **Live Packet Capture Integration**: Connect to Scapy or libpcap to ingest live socket telemetry in real-time.
- **Deep Learning Upgrades**: Incorporate LSTM/BERT transformers for contextual natural language email scanning.
- **Advanced XAI Graphs**: Utilize SHAP/LIME explanation plots directly in the web UI dashboard.
- **Webhooks**: Dispatch Slack or Discord notifications when critical-severity alerts are triggered.
