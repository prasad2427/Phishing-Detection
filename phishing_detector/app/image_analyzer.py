import cv2
import numpy as np
from PIL import Image
import pytesseract

class ImageAnalyzer:
    def analyze_bytes(self, image_bytes):
        try:
            nparr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if img is None:
                return {'verdict': 'clean', 'ocr_text': '', 'error': 'Invalid image'}
            
            # OCR with Tesseract
            pil_img = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
            ocr_text = pytesseract.image_to_string(pil_img)
            
            # Heuristic: if suspicious words in OCR
            suspicious_words = ["login", "verify", "secure", "bank", "password"]
            found = [w for w in suspicious_words if w in ocr_text.lower()]
            
            verdict = "suspicious" if found else "clean"
            
            return {
                'verdict': verdict,
                'ocr_text': ocr_text.strip(),
                'matched_keywords': found
            }
        except Exception as e:
            return {'verdict': 'error', 'error': str(e)}

    def analyze_screenshot(self, image_path):
        with open(image_path, 'rb') as f:
            return self.analyze_bytes(f.read())
