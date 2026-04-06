# core/analyzer.py
import re
import requests
from typing import Dict, List, Set
import urllib3

# Membungkam warning SSL saat JS Parser bekerja
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class MeowAnalyzer:
    def __init__(self):
        # Database Pola Rahasia (Regex)
        self.secret_patterns = {
            "AWS Access Key": r"(?i)AKIA[0-9A-Z]{16}",
            "JWT Token": r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "Generic API Key / Token": r"(?i)(?:api_key|apikey|secret|token|bearer)[\s=:\'\"]+([a-zA-Z0-9_\-]{20,})"
        }

        # Database Risiko Parameter
        self.param_risks = {
            "SSRF / Open Redirect": ["url", "uri", "redirect", "next", "dest", "path", "return", "window", "to"],
            "IDOR / SQLi": ["id", "user", "account", "number", "order", "no", "doc", "key", "email", "group", "profile"],
            "LFI / Path Traversal": ["file", "document", "folder", "root", "path", "pg", "style", "pdf", "template", "include", "dir"]
        }

    def classify_endpoints(self, endpoints: List[str]) -> Dict[str, int]:
        """Memisahkan URL ke dalam kategori spesifik"""
        classification = {"API": 0, "Auth": 0, "Admin": 0, "Static": 0, "JS": 0}
        
        for url in endpoints:
            url_lower = url.lower()
            if any(ext in url_lower for ext in [".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".ttf", ".ico"]):
                classification["Static"] += 1
            elif ".js" in url_lower:
                classification["JS"] += 1
            elif any(kw in url_lower for kw in ["/api/", "/v1/", "/v2/", "graphql", "rest"]):
                classification["API"] += 1
            elif any(kw in url_lower for kw in ["login", "signin", "register", "auth", "oauth", "sso"]):
                classification["Auth"] += 1
            elif any(kw in url_lower for kw in ["admin", "dashboard", "setup", "config", "panel"]):
                classification["Admin"] += 1
                
        return classification

    def parse_javascript(self, endpoints: List[str]) -> List[str]:
        """Mengunduh dan mengekstrak rahasia dari file JS"""
        js_urls = [u for u in endpoints if ".js" in u.lower()]
        found_secrets = set()
        headers = {"User-Agent": "Mozilla/5.0"}

        # Membatasi analisis ke 30 JS pertama agar scan tidak memakan waktu berjam-jam
        for js_url in js_urls[:30]:
            try:
                # Cek on-the-fly dengan timeout sangat cepat (3 detik)
                res = requests.get(js_url, headers=headers, timeout=3, verify=False)
                if res.status_code == 200:
                    content = res.text
                    for secret_name, pattern in self.secret_patterns.items():
                        if re.search(pattern, content):
                            found_secrets.add(f"Terekspos {secret_name} pada file: {js_url.split('/')[-1]}")
            except Exception:
                continue

        return list(found_secrets)

    def analyze_parameters(self, endpoints: List[str]) -> List[str]:
        """Menganalisis nama parameter untuk memetakan jenis serangan Logic Bug"""
        actions = set()
        for url in endpoints:
            if "?" not in url: continue
            
            # Ekstrak semua nama parameter (contoh: url.com?id=1&next=url -> ['id', 'next'])
            query_string = url.split("?")[1]
            params = [p.split("=")[0].lower() for p in query_string.split("&") if "=" in p]

            for param in params:
                for risk_type, keywords in self.param_risks.items():
                    if param in keywords:
                        actions.add(f"Test manual {risk_type} pada parameter '?{param}=' yang terdeteksi.")
        
        return list(actions)
