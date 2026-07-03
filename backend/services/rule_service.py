import re
from typing import Dict, Any

# --- FILE EXTENSION SCANNER ---
UNSAFE_EXTENSIONS = {
    ".exe": ("Executable application file - high hazard of malware execution.", "Critical"),
    ".bat": ("Windows Batch script - can execute arbitrary DOS commands.", "High"),
    ".vbs": ("VBScript file - often used in macro and email attachment malware.", "High"),
    ".scr": ("Screensaver file - executable under standard Windows shell.", "Critical"),
    ".ps1": ("PowerShell Script - can execute administrative commands.", "Critical"),
    ".js": ("Javascript script file - executes locally via Windows Script Host.", "Medium"),
    ".dll": ("Dynamic Link Library - can inject malicious code into processes.", "Critical"),
    ".cmd": ("Windows Command script - runs command-line commands.", "High")
}

def scan_file_extension(filename: str, ext: str) -> Dict[str, Any]:
    ext_lower = ext.lower().strip()
    if not ext_lower.startswith("."):
        ext_lower = "." + ext_lower
        
    filename_lower = filename.lower()
    
    reasons = []
    suggestions = []
    verdict = "Safe"
    risk_level = "Low"
    is_unsafe = False
    
    # Check 1: Double extension anomaly (e.g. file.pdf.exe)
    parts = filename_lower.split(".")
    # If the file has a double extension (e.g., more than one dot and the second to last is a normal extension)
    has_double_ext = False
    if len(parts) > 2:
        second_to_last_ext = "." + parts[-2]
        common_safe_exts = [".pdf", ".docx", ".xlsx", ".txt", ".png", ".jpg", ".zip"]
        if second_to_last_ext in common_safe_exts:
            has_double_ext = True
            reasons.append(f"Double extension masquerading detected: '{second_to_last_ext}{ext_lower}'")
            risk_level = "Critical"
            verdict = "Dangerous"
            is_unsafe = True

    # Check 2: Raw unsafe extension check
    if ext_lower in UNSAFE_EXTENSIONS:
        desc, severity = UNSAFE_EXTENSIONS[ext_lower]
        reasons.append(f"Dangerous extension found: '{ext_lower}'. {desc}")
        is_unsafe = True
        verdict = "Dangerous"
        # Take the maximum of double ext severity or raw ext severity
        if risk_level != "Critical":
            risk_level = severity
    
    if not is_unsafe:
        reasons.append(f"File extension '{ext_lower}' is registered as safe for standard operations.")
        suggestions = ["Normal file validation. Keep anti-virus shields active."]
    else:
        suggestions = [
            "Do NOT open, double-click, or execute this file.",
            "Inspect the origin/sender who provided this file vector.",
            "Submit the file to a sandbox environment or virus total scanner for signature checking."
        ]
        
    return {
        "verdict": verdict,
        "is_unsafe": is_unsafe,
        "explanation": {
            "verdict": verdict,
            "threat_type": "Malicious File Extension" if is_unsafe else "Safe File",
            "confidence": 99.0 if is_unsafe else 100.0,
            "risk_level": risk_level,
            "reasons": reasons,
            "suggestions": suggestions,
            "features_triggered": {"double_extension": has_double_ext, "extension": ext_lower}
        }
    }


# --- SQL INJECTION DETECTOR ---
SQL_KEYWORDS = [
    (r"(?i)\bUNION\b.*\bSELECT\b", "UNION SELECT query bypass"),
    (r"(?i)\bSELECT\b.*\bFROM\b", "Unauthorized SELECT database query"),
    (r"(?i)\bDROP\b\s+\bTABLE\b", "Database table DROP command"),
    (r"(?i)\bINSERT\b\s+\bINTO\b", "Database INSERT command"),
    (r"(?i)\bDELETE\b\s+\bFROM\b", "Database DELETE command"),
    (r"(?i)\bEXEC(\b|\s+|\()", "Database shell execution block (EXEC)"),
    (r"(?i)\bxp_cmdshell\b", "SQL Server shell injection (xp_cmdshell)"),
    (r"(?i)\bOR\b\s+\d+\s*=\s*\d+", "Tautology pattern bypass (e.g. OR 1=1)"),
    (r"(?i)'\s*OR\s*'\d+'\s*=\s*'\d+", "Tautology quote bypass (e.g. ' OR '1'='1)")
]

def scan_sql_injection(query_text: str) -> Dict[str, Any]:
    triggered = []
    
    for pattern, reason in SQL_KEYWORDS:
        if re.search(pattern, query_text):
            triggered.append(reason)
            
    is_injection = len(triggered) > 0
    verdict = "Dangerous" if is_injection else "Safe"
    risk_level = "Critical" if is_injection else "Low"
    confidence = 95.0 if is_injection else 100.0
    
    reasons = triggered if is_injection else ["No SQL injection patterns matched."]
    suggestions = []
    if is_injection:
        suggestions = [
            "Use parameterized SQL query statements or ORMs.",
            "Sanitize input forms using strict white-list regex filters.",
            "Apply principle of least privilege permissions to database user connection profiles."
        ]
    else:
        suggestions = ["Standard input query validation. Keep input validation frameworks active."]

    return {
        "verdict": verdict,
        "is_injection": is_injection,
        "explanation": {
            "verdict": verdict,
            "threat_type": "SQL Injection Attack" if is_injection else "Safe Input Query",
            "confidence": confidence,
            "risk_level": risk_level,
            "reasons": reasons,
            "suggestions": suggestions,
            "features_triggered": {"matched_rules_count": len(triggered), "rules": triggered}
        }
    }


# --- XSS DETECTOR ---
XSS_PATTERNS = [
    (r"(?i)<script\b[^>]*>", "Script tag block injection (<script>)"),
    (r"(?i)\bon\w+\s*=", "HTML attribute script event handler (e.g. onerror, onload)"),
    (r"(?i)javascript\s*:", "Javascript inline protocol header (javascript:)"),
    (r"(?i)<iframe\b[^>]*>", "IFrame clickjacking wrapper frame (<iframe)"),
    (r"(?i)alert\s*\(", "Execution call to display alerts (alert())"),
    (r"(?i)document\.cookie", "Cookie session hijacking command (document.cookie)")
]

def scan_xss(payload_text: str) -> Dict[str, Any]:
    triggered = []
    
    for pattern, reason in XSS_PATTERNS:
        if re.search(pattern, payload_text):
            triggered.append(reason)
            
    is_xss = len(triggered) > 0
    verdict = "Dangerous" if is_xss else "Safe"
    risk_level = "High" if is_xss else "Low"
    confidence = 96.0 if is_xss else 100.0
    
    reasons = triggered if is_xss else ["No XSS payloads matched."]
    suggestions = []
    if is_xss:
        suggestions = [
            "Perform HTML Entity Encoding on all user inputs before displaying them.",
            "Set strict Content Security Policy (CSP) headers.",
            "Implement HttpOnly and Secure attributes on cookies."
        ]
    else:
        suggestions = ["Standard input script validation. Safe to display."]

    return {
        "verdict": verdict,
        "is_xss": is_xss,
        "explanation": {
            "verdict": verdict,
            "threat_type": "XSS Injection Attack" if is_xss else "Safe Form Input",
            "confidence": confidence,
            "risk_level": risk_level,
            "reasons": reasons,
            "suggestions": suggestions,
            "features_triggered": {"matched_rules_count": len(triggered), "rules": triggered}
        }
    }


# --- LOGIN MONITOR ---
def scan_login_attempts(username: str, ip_address: str, failed_count: int, window: int) -> Dict[str, Any]:
    is_brute_force = False
    verdict = "Safe"
    risk_level = "Low"
    reasons = []
    suggestions = []
    confidence = 100.0

    if failed_count >= 5:
        is_brute_force = True
        verdict = "Dangerous"
        risk_level = "Critical"
        confidence = 98.0
        reasons.append(f"Brute-force attack warning: Account '{username}' triggered {failed_count} failed logins within {window} seconds from IP {ip_address}.")
    elif failed_count >= 3:
        is_brute_force = True
        verdict = "Suspicious"
        risk_level = "Medium"
        confidence = 80.0
        reasons.append(f"Multiple failed logins detected: {failed_count} failures for user '{username}' on host {ip_address}.")
    else:
        reasons.append(f"Normal access rate: {failed_count} login failures on record.")
        
    if is_brute_force:
        suggestions = [
            "Temporarily lock the user account or block requests from this source IP.",
            "Require Multi-Factor Authentication (MFA) challenge validation.",
            "Alert the account owner about unauthorized access attempts."
        ]
    else:
        suggestions = ["Normal logins audit logs. Keep access control systems active."]

    return {
        "verdict": verdict,
        "is_brute_force": is_brute_force,
        "explanation": {
            "verdict": verdict,
            "threat_type": "Brute Force Attack" if is_brute_force else "Normal Login Activity",
            "confidence": confidence,
            "risk_level": risk_level,
            "reasons": reasons,
            "suggestions": suggestions,
            "features_triggered": {"failed_attempts": failed_count, "ip": ip_address}
        }
    }
