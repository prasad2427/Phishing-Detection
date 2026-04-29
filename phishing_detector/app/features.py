import re
import socket
import ssl
import tldextract
import whois
import requests
from urllib.parse import urlparse
from datetime import datetime

FEATURE_NAMES = [
    "having_ip_address", "url_length", "shortening_service", "having_at_symbol",
    "double_slash_redirect", "prefix_suffix", "sub_domain_count", "https_token",
    "request_url_ratio", "url_of_anchor", "sfh", "submitting_to_email",
    "abnormal_url", "suspicious_words", "dns_record", "web_traffic",
    "page_rank", "google_index", "domain_age", "domain_reg_len",
    "ssl_final_state", "statistical_report", "port_status", "https_in_domain",
    "favicon", "popup_window", "iframe_redirection", "mouse_over",
    "right_click_disabled", "links_in_tags"
]

class FeatureExtractor:
    def __init__(self):
        self.shortening_list = [
            "bit.ly", "tinyurl.com", "goo.gl", "rebrand.ly", "t.co", "ow.ly", 
            "is.gd", "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr"
        ]
        self.suspicious_list = ["login", "verify", "secure", "bank", "password", "account", "update"]

    def extract_all(self, url, fast=True):
        try:
            features = {}
            extracted = tldextract.extract(url)
            parsed = urlparse(url)
            domain = extracted.domain + "." + extracted.suffix
            subdomain = extracted.subdomain
            path = parsed.path

            # --- Category 1: Address Bar Features (14 Features) ---
            
            # 1. having_ip_address
            ip_pattern = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
            features['having_ip_address'] = -1 if re.search(ip_pattern, url) else 1
            
            # 2. url_length
            url_len = len(url)
            if url_len < 54: features['url_length'] = 1
            elif 54 <= url_len <= 75: features['url_length'] = 0
            else: features['url_length'] = -1
            
            # 3. shortening_service
            features['shortening_service'] = -1 if any(s in url for s in self.shortening_list) else 1
            
            # 4. having_at_symbol
            features['having_at_symbol'] = -1 if '@' in url else 1
            
            # 5. double_slash_redirect
            features['double_slash_redirect'] = -1 if url.rfind('//') > 7 else 1
            
            # 6. prefix_suffix
            features['prefix_suffix'] = -1 if '-' in extracted.domain else 1
            
            # 7. sub_domain_count
            dot_count = subdomain.count('.')
            if dot_count == 0: features['sub_domain_count'] = 1
            elif dot_count == 1: features['sub_domain_count'] = 0
            else: features['sub_domain_count'] = -1
            
            # 8. https_token
            features['https_token'] = 1 if parsed.scheme == 'https' else -1
            
            # 9. request_url_ratio
            digit_count = len(re.findall(r'\d', path))
            ratio = digit_count / len(path) if len(path) > 0 else 0
            features['request_url_ratio'] = 1 if ratio < 0.2 else -1
            
            # 10. url_of_anchor
            anchor_patterns = ["redirect", "redir", "url=", "link="]
            features['url_of_anchor'] = -1 if any(p in url for p in anchor_patterns) else 1
            
            # 11. sfh
            features['sfh'] = -1 if "about:blank" in url or "javascript:" in url else 1
            
            # 12. submitting_to_email
            features['submitting_to_email'] = -1 if "mailto:" in url else 1
            
            # 13. abnormal_url
            features['abnormal_url'] = 1 if extracted.domain in url else -1
            
            # 14. suspicious_words
            features['suspicious_words'] = -1 if any(w in url.lower() for w in self.suspicious_list) else 1

            # --- Category 2: Domain Features (9 Features) ---
            
            # 15. dns_record
            if fast:
                features['dns_record'] = 1 # Skip in fast mode
            else:
                try:
                    socket.setdefaulttimeout(2)
                    socket.gethostbyname(domain)
                    features['dns_record'] = 1
                except:
                    features['dns_record'] = -1

            # 16. web_traffic
            features['web_traffic'] = 1 if extracted.suffix in ['com', 'org', 'net', 'edu', 'gov'] and len(extracted.domain) > 3 else -1
            
            # 17. page_rank
            features['page_rank'] = -1 if any(c.isdigit() or c == '-' for c in extracted.domain) else 1
            
            # 18. google_index
            features['google_index'] = 1 if parsed.scheme == 'https' and extracted.suffix in ['com', 'org', 'net', 'edu', 'gov'] else 0

            # 19. domain_age
            if fast:
                features['domain_age'] = 1 # Skip in fast mode
            else:
                try:
                    w = whois.whois(domain)
                    creation_date = w.creation_date
                    if isinstance(creation_date, list): creation_date = creation_date[0]
                    age = (datetime.now() - creation_date).days
                    features['domain_age'] = 1 if age > 180 else -1
                except:
                    features['domain_age'] = -1

            # 20. domain_reg_len
            if fast:
                features['domain_reg_len'] = 1 # Skip in fast mode
            else:
                try:
                    w = whois.whois(domain)
                    expiration_date = w.expiration_date
                    if isinstance(expiration_date, list): expiration_date = expiration_date[0]
                    remaining = (expiration_date - datetime.now()).days
                    features['domain_reg_len'] = 1 if remaining > 365 else -1
                except:
                    features['domain_reg_len'] = -1

            # 21. ssl_final_state
            if fast:
                features['ssl_final_state'] = 1 if parsed.scheme == 'https' else -1
            else:
                if parsed.scheme == 'https':
                    try:
                        requests.get(url, timeout=3, verify=True)
                        features['ssl_final_state'] = 1
                    except:
                        features['ssl_final_state'] = 0
                else:
                    features['ssl_final_state'] = -1

            # 22. statistical_report
            has_suspicious = any(w in url.lower() for w in self.suspicious_list)
            has_ip = re.search(ip_pattern, url)
            features['statistical_report'] = -1 if has_suspicious and has_ip else 1

            # 23. port_status
            features['port_status'] = 1 if parsed.port in [None, 80, 443] else -1

            # --- Category 3: HTML/Content Features (7 Features) ---
            
            # 24. https_in_domain
            features['https_in_domain'] = -1 if 'https' in domain.lower() else 1
            
            # 25. favicon
            features['favicon'] = 1
            
            # 26. popup_window
            features['popup_window'] = 1
            
            # 27. iframe_redirection
            features['iframe_redirection'] = 1
            
            # 28. mouse_over
            features['mouse_over'] = 1
            
            # 29. right_click_disabled
            features['right_click_disabled'] = 1
            
            # 30. links_in_tags
            features['links_in_tags'] = 1

            return features
        except Exception:
            # Return -1 for all 30 features on failure
            return {name: -1 for name in FEATURE_NAMES}

    def get_feature_vector(self, url, fast=True):
        feats = self.extract_all(url, fast=fast)
        return [feats[name] for name in FEATURE_NAMES]

def extract_all(url, fast=True):
    extractor = FeatureExtractor()
    return extractor.extract_all(url, fast=fast)

def get_feature_vector(url, fast=True):
    extractor = FeatureExtractor()
    return extractor.get_feature_vector(url, fast=fast)
