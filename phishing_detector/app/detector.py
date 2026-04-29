import joblib
import os
import requests
import re
from pathlib import Path
from .features import extract_all, get_feature_vector, FEATURE_NAMES

MODEL_PATH = Path(__file__).parent.parent / 'ml_model' / 'phishing_model.pkl'
_cache = None

REASON_MAPPING = {
    'having_ip_address': 'URL uses raw IP address',
    'url_length': 'URL length is suspiciously long',
    'shortening_service': 'Uses URL shortening service',
    'having_at_symbol': 'Contains @ symbol used for spoofing',
    'double_slash_redirect': 'Double slash redirect detected',
    'prefix_suffix': 'Hyphen in domain name (common in phishing)',
    'sub_domain_count': 'Excessive subdomains detected',
    'https_token': 'Uses HTTP instead of HTTPS',
    'request_url_ratio': 'High digit-to-path ratio',
    'url_of_anchor': 'Suspicious redirect parameters found',
    'sfh': 'URL points to blank or javascript execution',
    'submitting_to_email': 'Contains mailto: link prompting for credentials',
    'abnormal_url': 'Domain name not found in URL structure',
    'suspicious_words': 'Contains suspicious keywords (login, bank, etc.)',
    'dns_record': 'No valid DNS record found',
    'web_traffic': 'Low or unusual domain popularity',
    'page_rank': 'Low quality domain indicators',
    'google_index': 'Not indexed by Google (new/unverified site)',
    'domain_age': 'Domain age is too young or unknown',
    'domain_reg_len': 'Short domain registration period',
    'ssl_final_state': 'SSL handshake failed or insecure',
    'statistical_report': 'Matches known malicious profiles',
    'port_status': 'Uses non-standard port',
    'https_in_domain': 'HTTPS keyword found inside domain name',
}

def _load_model():
    global _cache
    if _cache is None:
        if os.path.exists(MODEL_PATH):
            try:
                _cache = joblib.load(MODEL_PATH)
            except Exception as e:
                print(f"Error loading model: {e}")
                return None
    return _cache

def classify_url(url, fast=True):
    try:
        # Load model and features
        model_data = _load_model()
        features_dict = extract_all(url, fast=fast)
        vector = [features_dict.get(name, -1) for name in FEATURE_NAMES]
        
        phish_prob = 0.0
        prediction = 'legitimate'
        
        if model_data:
            model = model_data['model']
            # Vector for model prediction
            X = [vector]
            # XGBoost output class 1 = Phishing (from our training mapping)
            if hasattr(model, 'predict_proba'):
                probs = model.predict_proba(X)[0]
                phish_prob = float(probs[1]) # Index 1 is phishing probability
            else:
                pred = model.predict(X)[0]
                phish_prob = 1.0 if pred == 1 else 0.0
            
            prediction = 'phishing' if phish_prob >= 0.5 else 'legitimate'
        else:
            # Heuristic fallback if model not available
            suspicious_count = sum(1 for v in vector if v == -1)
            phish_prob = min(1.0, suspicious_count / 10.0)
            prediction = 'phishing' if phish_prob >= 0.5 else 'legitimate'

        # Reasons (Initial extraction)
        reasons = [REASON_MAPPING[name] for name in FEATURE_NAMES if features_dict.get(name) == -1 and name in REASON_MAPPING]

        # PhishTank Check (Only for predicted phishing)
        phishtank_hit = False
        if prediction == 'phishing':
            try:
                # Add User-Agent as per PhishTank API recommendations
                headers = {'User-Agent': 'phishtank/phishing-detector-app'}
                pt_response = requests.post(
                    'https://checkurl.phishtank.com/checkurl/',
                    data={'url': url, 'format': 'json'},
                    headers=headers,
                    timeout=5
                )
                if pt_response.status_code == 200:
                    pt_data = pt_response.json()
                    results = pt_data.get('results', {})
                    phishtank_hit = results.get('in_database', False)
                    if phishtank_hit:
                        print(f"[INFO] PhishTank Hit: {url}")
                        reasons.append("Blacklisted in PhishTank database (Global Community Verification)")
                        phish_prob = max(phish_prob, 0.999)
                        prediction = 'phishing'
            except Exception as e:
                print(f"[WARN] PhishTank check failed: {e}")
                phishtank_hit = False

        # Risk Level
        risk_level = "LOW"
        if phish_prob > 0.8: risk_level = "HIGH"
        elif phish_prob >= 0.5: risk_level = "MEDIUM"
        else: risk_level = "LOW" # Explicitly match < 0.5 -> LOW

        return {
            "url": url,
            "prediction": prediction,
            "confidence": round(phish_prob, 4),
            "phishtank_hit": phishtank_hit,
            "risk_level": risk_level,
            "features": features_dict,
            "reasons": reasons
        }

    except Exception as e:
        return {
            "url": url,
            "prediction": "error",
            "confidence": 0.0,
            "error": str(e),
            "status": "failed"
        }

class PhishingDetector:
    def predict(self, url):
        return classify_url(url, fast=True)
