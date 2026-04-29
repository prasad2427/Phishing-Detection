import cv2
import numpy as np
import re
from pyzbar.pyzbar import decode, ZBarSymbol
from .detector import classify_url

class QRScanner:
    def scan_bytes(self, image_bytes):
        try:
            # 1. Load image bytes → cv2.imdecode
            nparr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if img is None:
                return {"qr_codes_found": 0, "results": [], "overall_verdict": "no_qr"}

            # 2. Try pyzbar.decode(img, symbols=[ZBarSymbol.QRCODE])
            decoded_objects = decode(img, symbols=[ZBarSymbol.QRCODE])

            # 3. If empty: convert to grayscale → OTSU threshold → try again
            if not decoded_objects:
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
                decoded_objects = decode(thresh, symbols=[ZBarSymbol.QRCODE])

            results = []
            has_phishing = False
            has_url = False

            for obj in decoded_objects:
                # 4. Decode each result.data as UTF-8
                try:
                    raw_data = obj.data.decode('utf-8')
                except:
                    continue

                # Check if raw_data starts with http/https/www → is_url = True
                is_url = False
                classification = {}
                
                normalized_data = raw_data.strip()
                if re.match(r'^(http|https|www\.)', normalized_data, re.IGNORECASE):
                    is_url = True
                    has_url = True
                    # Normalize to full URL
                    if normalized_data.lower().startswith('www.'):
                        url = 'http://' + normalized_data
                    elif not normalized_data.lower().startswith('http'):
                        url = 'http://' + normalized_data
                    else:
                        url = normalized_data
                    
                    # Call classify_url(url, fast=True)
                    classification = classify_url(url, fast=True)
                    if classification.get('prediction') == 'phishing':
                        has_phishing = True
                
                results.append({
                    "raw_data": raw_data,
                    "is_url": is_url,
                    "classification": classification
                })

            # overall_verdict: 'phishing' if any is phishing, 'suspicious' if URLs found but not phishing, 
            # 'clean' if no URLs, 'no_qr' if nothing decoded.
            if not results:
                verdict = "no_qr"
            elif has_phishing:
                verdict = "phishing"
            elif has_url:
                verdict = "suspicious"
            else:
                verdict = "clean"

            return {
                "qr_codes_found": len(results),
                "results": results,
                "overall_verdict": verdict
            }

        except Exception as e:
            print(f"QR Scanner Error: {e}")
            return {
                "qr_codes_found": 0,
                "results": [],
                "overall_verdict": "error",
                "error": str(e)
            }

    def scan(self, image_path):
        # Helper for file paths
        with open(image_path, 'rb') as f:
            return self.scan_bytes(f.read())
