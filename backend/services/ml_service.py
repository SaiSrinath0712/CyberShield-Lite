import os
import joblib
import numpy as np
import math
import re
from typing import Dict, Any, List

# Target folder for ML models
ML_MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "ml_models")
PHISHING_MODEL_PATH = os.path.join(ML_MODELS_DIR, "phishing_model.pkl")
PHISHING_VEC_PATH = os.path.join(ML_MODELS_DIR, "vectorizer.pkl")
URL_MODEL_PATH = os.path.join(ML_MODELS_DIR, "url_model.pkl")
IDS_MODEL_PATH = os.path.join(ML_MODELS_DIR, "ids_model.pkl")

# Heuristic Fallback Classifiers (ensures code runs before train script completes)
class HeuristicPhishingClassifier:
    KEYWORDS = ["verify", "urgent", "account", "bank", "suspend", "security", "update", "click", "login", "winner", "free", "claim", "paypal"]
    
    def predict_proba(self, text: str) -> np.ndarray:
        text_lower = text.lower()
        score = sum(0.2 for kw in self.KEYWORDS if kw in text_lower)
        score = min(score, 0.98)
        if score == 0:
            return np.array([[0.95, 0.05]])
        return np.array([[1.0 - score, score]])

class HeuristicURLClassifier:
    def predict_proba(self, features: np.ndarray) -> np.ndarray:
        # features: [length, dots, specials, is_ip, is_https, is_shortened, keywords_count, subdomains, entropy]
        feat = features[0]
        risk = 0.02
        if feat[4] == 0: risk += 0.30  # missing HTTPS
        if feat[3] == 1: risk += 0.35  # uses IP
        if feat[5] == 1: risk += 0.20  # shortened URL
        risk += feat[6] * 0.15          # keywords count
        if feat[8] > 4.5: risk += 0.15  # high entropy
        risk = min(risk, 0.99)
        return np.array([[1.0 - risk, risk]])

class HeuristicIDSClassifier:
    def predict(self, features: np.ndarray) -> np.ndarray:
        serror_rate = features[0][7]  # serror_rate
        count = features[0][6]       # count
        failed_logins = features[0][8] # failed_logins
        
        if serror_rate > 0.7 and count > 30:
            return np.array([1])  # DoS
        elif failed_logins > 2:
            return np.array([3])  # R2L (Brute Force)
        elif count > 50:
            return np.array([2])  # Probe
        return np.array([0])      # normal

    def predict_proba(self, features: np.ndarray) -> np.ndarray:
        pred = self.predict(features)[0]
        if pred == 0:
            return np.array([[0.95, 0.05, 0.0, 0.0, 0.0]])
        proba = [0.0] * 5
        proba[pred] = 0.90
        proba[0] = 0.10
        return np.array([proba])


class MLService:
    def __init__(self):
        self.phishing_model = None
        self.vectorizer = None
        self.url_model = None
        self.ids_model = None
        self.load_models()

    def load_models(self):
        """Loads machine learning models from disk. Falls back to rules if missing."""
        # Phishing Email
        if os.path.exists(PHISHING_MODEL_PATH) and os.path.exists(PHISHING_VEC_PATH):
            try:
                self.phishing_model = joblib.load(PHISHING_MODEL_PATH)
                self.vectorizer = joblib.load(PHISHING_VEC_PATH)
                print("[MLService] Phishing model loaded.")
            except Exception:
                pass
        if not self.phishing_model:
            self.phishing_model = HeuristicPhishingClassifier()
            self.vectorizer = None

        # URL Model
        if os.path.exists(URL_MODEL_PATH):
            try:
                self.url_model = joblib.load(URL_MODEL_PATH)
                print("[MLService] URL model loaded.")
            except Exception:
                pass
        if not self.url_model:
            self.url_model = HeuristicURLClassifier()

        # IDS Model
        if os.path.exists(IDS_MODEL_PATH):
            try:
                self.ids_model = joblib.load(IDS_MODEL_PATH)
                print("[MLService] IDS model loaded.")
            except Exception:
                pass
        if not self.ids_model:
            self.ids_model = HeuristicIDSClassifier()

    @staticmethod
    def calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def extract_url_features(self, url: str) -> np.ndarray:
        length = len(url)
        dots = url.count(".")
        specials = sum(1 for c in url if c in ["-", "@", "?", "=", "&", "_", "%"])
        ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
        is_ip = 1 if re.search(ip_pattern, url) else 0
        is_https = 1 if url.lower().startswith("https") else 0
        shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]
        is_shortened = 1 if any(s in url.lower() for s in shorteners) else 0
        keywords = ["login", "signin", "bank", "secure", "update", "paypal", "verify", "account"]
        keywords_count = sum(1 for kw in keywords if kw in url.lower())
        parsed = re.sub(r"^https?://", "", url).split("/")[0]
        subdomains = max(0, parsed.count(".") - 1)
        entropy = self.calculate_entropy(url)

        return np.array([[length, dots, specials, is_ip, is_https, is_shortened, keywords_count, subdomains, entropy]], dtype=float)

    # --- INFERENCE & XAI PIPELINES ---

    def check_email(self, subject: str, body: str) -> Dict[str, Any]:
        full_text = f"{subject} {body}"
        triggered_keywords = [kw for kw in HeuristicPhishingClassifier.KEYWORDS if kw in full_text.lower()]
        
        if self.vectorizer and hasattr(self.phishing_model, "predict_proba"):
            try:
                vec_text = self.vectorizer.transform([full_text])
                proba = self.phishing_model.predict_proba(vec_text)[0]
                pred_idx = np.argmax(proba)
                confidence = float(proba[pred_idx]) * 100.0
                is_phishing = bool(pred_idx == 1)
            except Exception:
                # fallback in case of vec errors
                is_phishing = len(triggered_keywords) > 0
                confidence = 90.0 if is_phishing else 95.0
        else:
            proba = self.phishing_model.predict_proba(full_text)[0]
            is_phishing = proba[1] > 0.40
            confidence = float(proba[1] if is_phishing else proba[0]) * 100.0

        verdict = "Dangerous" if is_phishing else ("Suspicious" if len(triggered_keywords) > 0 else "Safe")
        risk_level = "Low"
        if verdict == "Dangerous":
            risk_level = "High" if confidence > 80 else "Medium"
        elif verdict == "Suspicious":
            risk_level = "Medium"
            
        reasons = []
        suggestions = []
        
        if verdict == "Dangerous":
            reasons.append(f"Classified as Phishing Email signature with {confidence:.1f}% confidence.")
            if triggered_keywords:
                reasons.append(f"Urgent or sensitive keywords detected: {triggered_keywords}")
            suggestions = [
                "Do NOT click any links inside the email body.",
                "Verify the sender's domain address in the header.",
                "Mark as spam and report to security operations."
            ]
        elif verdict == "Suspicious":
            reasons.append("Email contains promotional keywords, resembling unsolicited Spam.")
            suggestions = ["Avoid replying to this message.", "Unsubscribe if sender is a registered newsletter."]
        else:
            reasons.append("Email structure has clean semantic characteristics.")
            suggestions = ["Normal email. Keep maintaining general security vigilance."]

        return {
            "verdict": verdict,
            "is_phishing": is_phishing or verdict == "Dangerous",
            "explanation": {
                "verdict": verdict,
                "threat_type": "Phishing Email" if verdict == "Dangerous" else ("Spam Email" if verdict == "Suspicious" else "Safe Email"),
                "confidence": round(confidence, 2),
                "risk_level": risk_level,
                "reasons": reasons,
                "suggestions": suggestions,
                "features_triggered": {"keywords_found": triggered_keywords}
            }
        }

    def check_url(self, url: str) -> Dict[str, Any]:
        features = self.extract_url_features(url)
        feat_list = features[0]
        length, dots, specials, is_ip, is_https, is_shortened, keywords_count, subdomains, entropy = feat_list

        if hasattr(self.url_model, "predict_proba"):
            proba = self.url_model.predict_proba(features)[0]
            pred_idx = np.argmax(proba)
            confidence = float(proba[pred_idx]) * 100.0
            is_malicious = bool(pred_idx == 1)
        else:
            is_malicious = False
            confidence = 100.0

        verdict = "Dangerous" if is_malicious else "Safe"
        risk_level = "Critical" if (is_malicious and is_ip == 1) else ("High" if is_malicious else "Low")
        
        reasons = []
        suggestions = []
        
        if is_malicious:
            reasons.append(f"URL classified as Malicious with {confidence:.1f}% confidence.")
            if is_https == 0:
                reasons.append("HTTP Connection: missing TLS transport encryption.")
            if is_ip == 1:
                reasons.append("Anomalous Host: utilizes raw numerical IP address.")
            if is_shortened == 1:
                reasons.append("Anomalous Host: utilizes link-shortener domain mask.")
            if keywords_count > 0:
                reasons.append(f"Contains security-sensitive phrases (keywords matched: {int(keywords_count)}).")
            if length > 75:
                reasons.append(f"Anomalous Length: unusually long URL path ({int(length)} chars).")
            suggestions = [
                "Do NOT browse or type credentials on this website.",
                "Review the DNS registry profile using a whois lookup tool.",
                "Block outbound network traffic to this destination domain."
            ]
        else:
            reasons.append("URL structures conform to safe domain registry conventions.")
            suggestions = ["Clean website link. Always ensure HSTS certificate is valid when logging in."]

        return {
            "verdict": verdict,
            "is_malicious": is_malicious,
            "explanation": {
                "verdict": verdict,
                "threat_type": "Malicious URL" if is_malicious else "Safe URL",
                "confidence": round(confidence, 2),
                "risk_level": risk_level,
                "reasons": reasons,
                "suggestions": suggestions,
                "features_triggered": {
                    "length": int(length),
                    "dots": int(dots),
                    "is_ip": bool(is_ip),
                    "is_https": bool(is_https),
                    "is_shortened": bool(is_shortened)
                }
            }
        }

    def check_intrusion(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        # Simple simplified KDD mapping
        # features vector size 9: [duration, protocol, service, src_bytes, dst_bytes, count, serror_rate, failed_logins, SameSrvRate]
        protocols = {"tcp": 0, "udp": 1, "icmp": 2}
        services = {"http": 0, "smtp": 1, "ftp": 2, "private": 3, "other": 4}
        
        p_type = protocols.get(packet.get("protocol_type", "tcp").lower(), 0)
        srv = services.get(packet.get("service", "http").lower(), 0)
        
        # 9 simplified features
        features = [
            packet.get("duration", 0.0),
            p_type,
            srv,
            packet.get("src_bytes", 0),
            packet.get("dst_bytes", 0),
            packet.get("count", 1),
            packet.get("serror_rate", 0.0),
            packet.get("num_failed_logins", 0),
            1.0 if packet.get("flag", "SF") == "SF" else 0.0  # simple srv rate proxy
        ]
        
        feats_arr = np.array([features], dtype=float)
        attack_classes = ["normal", "DoS", "Probe", "R2L", "U2R"]

        if hasattr(self.ids_model, "predict"):
            pred_idx = self.ids_model.predict(feats_arr)[0]
            if hasattr(self.ids_model, "predict_proba"):
                proba = self.ids_model.predict_proba(feats_arr)[0]
                confidence = float(np.max(proba)) * 100.0
            else:
                confidence = 90.0
            
            # Map index
            if isinstance(pred_idx, (int, np.integer)):
                pred_label = attack_classes[int(pred_idx)]
            else:
                pred_label = str(pred_idx)
        else:
            pred_label = "normal"
            confidence = 95.0

        is_attack = pred_label.lower() != "normal"
        verdict = "Dangerous" if is_attack else "Safe"
        risk_level = "Low"
        reasons = []
        suggestions = []
        
        if is_attack:
            risk_level = "Critical" if pred_label in ["U2R", "R2L"] else "High"
            reasons.append(f"Network Intrusion Alert: Telemetry matched '{pred_label}' packet classification (Confidence: {confidence:.1f}%).")
            if packet.get("serror_rate", 0.0) > 0.6:
                reasons.append("Half-open connection flood anomaly (SYN flood indicator).")
            if packet.get("num_failed_logins", 0) > 2:
                reasons.append(f"Multiple login authentication failures ({packet['num_failed_logins']}) flagged on node.")
            suggestions = [
                "Trigger firewall black-list rules against the source client node.",
                "Rotate user credential profiles mapped to this workstation.",
                "Audit local logs directories for potential payload injections."
            ]
        else:
            reasons.append("Network session metrics correlate with normal connection parameters.")
            suggestions = ["Standard monitoring trace. Keep IDS sensors active."]

        return {
            "verdict": verdict,
            "is_attack": is_attack,
            "attack_type": pred_label,
            "explanation": {
                "verdict": verdict,
                "threat_type": f"Network Intrusion ({pred_label})" if is_attack else "Normal Traffic",
                "confidence": round(confidence, 2),
                "risk_level": risk_level,
                "reasons": reasons,
                "suggestions": suggestions,
                "features_triggered": {
                    "duration": float(packet.get("duration", 0.0)),
                    "src_bytes": int(packet.get("src_bytes", 0)),
                    "serror_rate": float(packet.get("serror_rate", 0.0)),
                    "failed_logins": int(packet.get("num_failed_logins", 0))
                }
            }
        }


ml_service = MLService()
