import re
from urllib.parse import urlparse
import tldextract

class LinkAnalyzer:
    SUSPICIOUS_TLDS = {'.ru', '.tk', '.xyz', '.date', '.top', '.pw', '.loan', '.click', '.monster', '.ga', '.cf', '.ml'}
    SHORTENERS = {'bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly'}

    def analyze(self, text: str):
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        results = []
        total_risk = 0

        for url in urls:
            risk = 0
            warnings = []
            parsed = urlparse(url)
            domain = parsed.netloc
            ext = tldextract.extract(url)
            
            # 1. HTTPS check
            if parsed.scheme != 'https':
                risk += 20
                warnings.append("Insecure Protocol (HTTP)")

            # 2. Suspicious TLD
            if f".{ext.suffix}" in self.SUSPICIOUS_TLDS:
                risk += 30
                warnings.append(f"Suspicious TLD (.{ext.suffix})")

            # 3. IP Based URL
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                risk += 40
                warnings.append("IP-based URL Detected")

            # 4. URL Shorteners
            if domain.lower() in self.SHORTENERS:
                risk += 25
                warnings.append("URL Shortener Detected")

            # 5. Typosquatting simulation (Basic check for common mocks like google -> g00gle)
            if re.search(r'[0-9]', domain) and not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                risk += 15
                warnings.append("Possible Typosquatting (Digits in domain)")

            # Normalize risk
            risk = min(risk, 100)
            total_risk += risk
            
            status = "Malicious" if risk > 60 else "Suspicious" if risk > 20 else "Safe"
            
            results.append({
                "url": url,
                "domain": domain,
                "risk_score": risk,
                "status": status,
                "warnings": warnings
            })

        avg_risk = (total_risk / len(urls)) if urls else 0
        return {
            "links": results,
            "link_risk_score": round(avg_risk, 2),
            "link_count": len(urls)
        }
