import os
import joblib
import smtplib
import ssl
from datetime import datetime
from email.mime.text import MIMEText
from flask import Blueprint, render_template, request, jsonify
from .detector import classify_url, MODEL_PATH
from .image_analyzer import ImageAnalyzer
from .qr_scanner import QRScanner

main_bp = Blueprint('main', __name__)
image_analyzer = ImageAnalyzer()
qr_scanner = QRScanner()

# In-memory scan log
scan_log = []
LOG_LIMIT = 500

def log_scan(scan_type, result):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": scan_type,
        **result
    }
    scan_log.insert(0, entry)
    if len(scan_log) > LOG_LIMIT:
        scan_log.pop()
    
    # Trigger Alerts
    trigger_alert = False
    if scan_type == 'url' and result.get('prediction') == 'phishing':
        trigger_alert = True
    elif scan_type == 'image' and result.get('verdict') == 'suspicious':
        trigger_alert = True
    elif scan_type == 'qr' and result.get('overall_verdict') == 'phishing':
        trigger_alert = True
        
    if trigger_alert:
        send_alert(scan_type, result)

def send_alert(scan_type, result):
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    alert_to = os.environ.get('ALERT_TO')
    
    if not all([smtp_user, smtp_pass, alert_to]):
        return

    try:
        subject = f"[PHISHING ALERT] {scan_type.upper()} Detection"
        if scan_type == 'url':
            subject = f"[PHISHING ALERT] {result.get('url')}"
            
        body = f"Suspicious activity detected!\n\nType: {scan_type}\nDetails: {result}"
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = smtp_user
        msg['To'] = alert_to

        context = ssl.create_default_context()
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls(context=context)
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
    except Exception as e:
        print(f"Failed to send email alert: {e}")

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/api/scan/url', methods=['POST'])
def scan_url():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    result = classify_url(url, fast=True)
    log_scan('url', result)
    return jsonify(result)

@main_bp.route('/api/scan/image', methods=['POST'])
def scan_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    img_bytes = file.read()
    
    result = image_analyzer.analyze_bytes(img_bytes)
    # Enrich result for logs
    result['confidence'] = 0.92 if result.get('verdict') == 'suspicious' else 0.05
    result['prediction'] = 'phishing' if result.get('verdict') == 'suspicious' else 'legitimate'
    
    log_scan('image', result)
    return jsonify(result)

@main_bp.route('/api/scan/qr', methods=['POST'])
def scan_qr():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    img_bytes = file.read()
    
    result = qr_scanner.scan_bytes(img_bytes)
    # Enrich result with top-level fields for consistent logging
    if result.get('qr_codes_found', 0) > 0:
        main_res = result['results'][0]
        result['url'] = main_res.get('raw_data')
        result['confidence'] = main_res.get('classification', {}).get('confidence', 0.0)
        result['prediction'] = main_res.get('classification', {}).get('prediction', 'legitimate')
    else:
        result['confidence'] = 0.0
        result['prediction'] = 'error'

    log_scan('qr', result)
    return jsonify(result)

@main_bp.route('/api/logs', methods=['GET'])
def get_logs():
    limit = request.args.get('limit', default=50, type=int)
    return jsonify(scan_log[:limit])

@main_bp.route('/api/stats', methods=['GET'])
def get_stats():
    total_scans = len(scan_log)
    phishing_found = sum(1 for log in scan_log if log.get('prediction') == 'phishing' or log.get('overall_verdict') == 'phishing')
    clean = total_scans - phishing_found
    
    accuracy = 0.0
    if os.path.exists(MODEL_PATH):
        try:
            model_data = joblib.load(MODEL_PATH)
            accuracy = model_data.get('accuracy', 0.0)
        except:
            pass
            
    return jsonify({
        "total_scans": total_scans,
        "phishing_found": phishing_found,
        "clean": clean,
        "accuracy": accuracy
    })

@main_bp.route('/api/health', methods=['GET'])
def health():
    model_loaded = os.path.exists(MODEL_PATH)
    return jsonify({
        "status": "ok",
        "model_loaded": model_loaded
    })
