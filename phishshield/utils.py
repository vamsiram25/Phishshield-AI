import re
import os

def analyze_links(text):
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    results = []
    total_score = 0
    
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'signin', 'confirm', 'billing']
    susp_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.ru', '.pw', '.bid', '.top']
    shorteners = ['bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly']
    
    for url in urls:
        score = 0
        warnings = []
        
        if not url.startswith('https'):
            score += 25
            warnings.append("Insecure (HTTP)")
            
        domain_match = re.search(r'https?://([^/]+)', url)
        if domain_match:
            domain_name = domain_match.group(1).lower()
            
            # 1. IP-based URL
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain_name):
                score += 40
                warnings.append("IP-based URL")
            
            # 2. Suspicious keywords in domain
            for kw in suspicious_keywords:
                if kw in domain_name:
                    score += 20
                    warnings.append(f"Tactical keyword: {kw}")
                    break
            
            # 3. Suspicious TLD
            for tld in susp_tlds:
                if domain_name.endswith(tld):
                    score += 30
                    warnings.append(f"Suspicious TLD: {tld}")
                    break
            
            # 4. URL Shortener
            for sh in shorteners:
                if sh in domain_name:
                    score += 25
                    warnings.append("URL Shortener (Obfuscation)")
                    break
            
            # 5. Long domain
            if len(domain_name) > 30:
                score += 15
                warnings.append("Anomalous domain length")

        score = min(score, 100)
        total_score += score
        results.append({"url": url, "score": score, "warnings": warnings})
        
    avg_score = (total_score / len(urls)) if urls else 0
    return {"links": results, "score": round(avg_score, 2), "count": len(urls)}

def analyze_attachment(filename, file_size):
    if not filename:
        return {"score": 0, "warnings": []}
        
    score = 0
    warnings = []
    
    ext = os.path.splitext(filename)[1].lower()
    dangerous = ['.exe', '.js', '.bat', '.scr', '.msi', '.vbs']
    
    if ext in dangerous:
        score += 60
        warnings.append(f"Dangerous extension: {ext}")
        
    # Double extension check
    if filename.count('.') > 1:
        base_parts = filename.split('.')
        if base_parts[-2].lower() in ['.pdf', '.doc', '.txt', '.jpg']:
             score += 30
             warnings.append("Hidden extension detected")
             
    # Size check (2MB limit for suspicious threshold)
    if file_size > 2 * 1024 * 1024:
        score += 10
        warnings.append("Unusually large attachment")
        
    return {"score": min(score, 100), "warnings": warnings, "filename": filename}

def calculate_final_risk(ml_score, link_score, attach_score, keyword_score):
    # Weighted calculation: ML (35%), Links (30%), Keywords (20%), Attachments (15%)
    final_score = (ml_score * 0.35) + (link_score * 0.30) + (keyword_score * 0.20) + (attach_score * 0.15)
    final_score = round(min(final_score, 100), 2)
    
    if final_score > 70:
        level = "High"
    elif final_score > 30:
        level = "Medium"
    else:
        level = "Low"
        
    return {"score": final_score, "level": level}
def generate_analysis_summary(ml_result, link_result, keyword_result, attach_result, final_risk):
    summary_parts = []
    
    # 1. ML Classifier Verdict
    if ml_result['score'] > 70:
        summary_parts.append(f"AI Neural Network has flagged this content as highly likely phishing (Confidence: {ml_result['score']}%).")
    elif ml_result['score'] > 40:
        summary_parts.append(f"AI patterns suggest moderate suspicion in content structure.")
        
    # 2. Link Analysis
    if link_result['count'] > 0:
        malicious_links = [l for l in link_result['links'] if l['score'] > 50]
        if malicious_links:
            summary_parts.append(f"Detected {len(malicious_links)} high-risk URLs featuring {malicious_links[0]['warnings'][0]}.")
        elif link_result['score'] > 20:
             summary_parts.append("Extracted URLs show anomalous characteristics like suspicious TLDs or obfuscated shorteners.")

    # 3. Keyword/Tactical Analysis
    if keyword_result['keyword_risk_score'] > 50:
        summary_parts.append("Critical linguistic vectors detected: content uses aggressive threat tactics and urgency to force user compliance.")
    elif keyword_result['keyword_risk_score'] > 0:
        summary_parts.append("Linguistic patterns show signs of social engineering, including financial bait and credential solicitation.")

    # 4. Attachment Analysis
    if attach_result['score'] > 50:
        summary_parts.append(f"Security sandbox flagged attachment '{attach_result['filename']}' due to dangerous extension or obfuscated metadata.")

    # Final Verdict
    if not summary_parts:
        return "No major tactical anomalies detected across analyzed vectors. The content appears consistent with legitimate communication."
    
    return " ".join(summary_parts)
