import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.rule_service import scan_file_extension

client = TestClient(app)

def test_file_extension_executables():
    """Verify that executable files (.exe, .scr, .bat, .ps1, etc.) are flagged as Dangerous."""
    for ext, name in [("exe", "test.exe"), ("scr", "screensaver.scr"), ("bat", "script.bat"), ("ps1", "admin.ps1"), ("msi", "setup.msi")]:
        res = scan_file_extension(name, ext)
        assert res["verdict"] == "Dangerous"
        assert res["is_unsafe"] is True
        assert res["explanation"]["risk_level"] in ["Critical", "High"]
        assert res["explanation"]["confidence"] >= 90.0

def test_file_extension_maldoc_macros():
    """Verify that weaponized macro documents (.docm, .xlsm, .pptm, etc.) are flagged as Dangerous."""
    for ext, name in [("docm", "invoice.docm"), ("xlsm", "salary.xlsm"), ("pptm", "deck.pptm")]:
        res = scan_file_extension(name, ext)
        assert res["verdict"] == "Dangerous"
        assert res["is_unsafe"] is True
        assert "Macro" in res["explanation"]["features_triggered"]["category"]
        assert res["explanation"]["risk_level"] == "High"

def test_file_extension_double_extension_spoofing():
    """Verify that double extension masquerading (e.g. invoice.pdf.exe or ext='.pdf.exe') is detected as Critical."""
    # Scenario 1: filename has double ext, ext is .exe
    res1 = scan_file_extension("invoice.pdf.exe", "exe")
    assert res1["verdict"] == "Dangerous"
    assert res1["explanation"]["threat_type"] == "Double Extension Spoofing"
    assert res1["explanation"]["risk_level"] == "Critical"
    assert res1["explanation"]["features_triggered"]["double_extension"] is True

    # Scenario 2 (User's exact case): filename is 'invoice', ext is '.pdf.exe'
    res2 = scan_file_extension("invoice", ".pdf.exe")
    assert res2["verdict"] == "Dangerous"
    assert res2["explanation"]["threat_type"] == "Double Extension Spoofing"
    assert res2["explanation"]["risk_level"] == "Critical"
    assert res2["explanation"]["features_triggered"]["double_extension"] is True

    # Scenario 3: Multiple non-executable extensions (e.g. .pdf.docx) should be Suspicious
    res3 = scan_file_extension("document", ".pdf.docx")
    assert res3["verdict"] == "Suspicious"
    assert res3["is_unsafe"] is True
    assert res3["explanation"]["risk_level"] == "Medium"

def test_file_extension_rtlo_spoofing():
    """Verify Right-to-Left Override Unicode character spoofing."""
    res = scan_file_extension("contract\u202egpj.exe", "jpg")
    assert res["verdict"] == "Dangerous"
    assert res["explanation"]["threat_type"] == "RTLO Masquerading Attack"
    assert res["explanation"]["risk_level"] == "Critical"
    assert res["explanation"]["features_triggered"]["rtlo_spoofing"] is True

def test_file_extension_safe_documents():
    """Verify standard legitimate documents and media files are classified as Safe."""
    for ext, name in [("pdf", "annual_report.pdf"), ("docx", "project_spec.docx"), ("xlsx", "budget.xlsx"), ("png", "diagram.png"), ("jpg", "photo.jpg"), ("txt", "notes.txt")]:
        res = scan_file_extension(name, ext)
        assert res["verdict"] == "Safe"
        assert res["is_unsafe"] is False
        assert res["explanation"]["risk_level"] == "Low"
        assert res["explanation"]["confidence"] >= 95.0

def test_file_extension_mismatch():
    """Verify filename extension conflicting with declared parameter extension."""
    res = scan_file_extension("document.exe", "pdf")
    assert res["verdict"] == "Dangerous"
    assert res["explanation"]["features_triggered"]["extension_mismatch"] is True

def test_api_predict_file_endpoint():
    """Test /predict/file HTTP API endpoint."""
    response = client.post("/predict/file", json={"filename": "malware.exe", "extension": "exe"})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "Dangerous"
    assert data["is_unsafe"] is True

def test_api_predict_email_phishing():
    """Test /predict/email with phishing payload."""
    response = client.post("/predict/email", json={
        "subject": "Urgent Security Alert",
        "body": "Your bank account has been locked. Verify immediately at http://secure-bank-login.xyz to avoid suspension."
    })
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "Dangerous"
    assert data["is_phishing"] is True

def test_api_predict_email_clean():
    """Test /predict/email with clean business communication."""
    response = client.post("/predict/email", json={
        "subject": "Team Sync",
        "body": "Hi team, let us meet for our sprint retrospective tomorrow morning at 10 AM in room 3."
    })
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "Safe"
    assert data["is_phishing"] is False

def test_api_predict_url():
    """Test /predict/url with phishing and legitimate URLs."""
    # Phishing
    r_bad = client.post("/predict/url", json={"url": "http://192.168.1.100/paypal/login.php"})
    assert r_bad.status_code == 200
    assert r_bad.json()["verdict"] == "Dangerous"

    # Clean
    r_good = client.post("/predict/url", json={"url": "https://github.com/torvalds/linux"})
    assert r_good.status_code == 200
    assert r_good.json()["verdict"] == "Safe"

def test_api_predict_intrusion():
    """Test /predict/intrusion for DoS attack vs normal packet."""
    r_dos = client.post("/predict/intrusion", json={
        "duration": 0.0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "S0",
        "src_bytes": 0,
        "dst_bytes": 0,
        "count": 300,
        "serror_rate": 1.0,
        "num_failed_logins": 0
    })
    assert r_dos.status_code == 200
    assert r_dos.json()["is_attack"] is True

    r_norm = client.post("/predict/intrusion", json={
        "duration": 1.0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 1200,
        "dst_bytes": 3500,
        "count": 2,
        "serror_rate": 0.0,
        "num_failed_logins": 0
    })
    assert r_norm.status_code == 200
    assert r_norm.json()["is_attack"] is False

def test_api_dashboard():
    """Test /dashboard telemetry statistics."""
    response = client.get("/dashboard")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "total_threats" in data
    assert "distribution" in data
