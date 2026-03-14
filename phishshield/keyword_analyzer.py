import re

class KeywordAnalyzer:
    CATEGORIES = {
        "Urgency/Time Pressure": {
            "keywords": ["urgent", "immediately", "within 24 hours", "act now", "limited time", "deadline", "fast"],
            "severity": "High",
            "score_per_word": 10,
            "explanation": "Language creates artificial urgency to force quick, uncritical decisions."
        },
        "Financial Context": {
            "keywords": ["bank", "account", "payment", "refund", "invoice", "transfer", "billing", "wire"],
            "severity": "Medium",
            "score_per_word": 7,
            "explanation": "Mentions of financial transactions are common bait in phishing attacks."
        },
        "Credential Harvesting": {
            "keywords": ["verify", "password", "login", "reset", "confirm identity", "credentials", "authentication"],
            "severity": "High",
            "score_per_word": 12,
            "explanation": "Attempts to solicit login credentials or verification are high-risk indicators."
        },
        "Threat/Fear Tactics": {
            "keywords": ["suspended", "restricted", "terminated", "legal action", "unauthorized", "crime", "alert"],
            "severity": "Critical",
            "score_per_word": 15,
            "explanation": "Threatening language is used to scare the recipient into compliance."
        },
        "Malware Indicators": {
            "keywords": [".exe", ".scr", ".zip", ".js", "macro", "enable content", "download"],
            "severity": "Critical",
            "score_per_word": 15,
            "explanation": "References to dangerous file types or content execution often precede malware delivery."
        }
    }

    def analyze(self, text):
        text_lower = text.lower()
        detected_words = []
        category_counts = {}
        total_risk = 0

        for category, data in self.CATEGORIES.items():
            category_score = 0
            for word in data["keywords"]:
                # Use regex to find whole words only
                pattern = r'\b' + re.escape(word) + r'\b'
                matches = re.finditer(pattern, text_lower)
                
                count = 0
                for match in matches:
                    count += 1
                    detected_words.append({
                        "word": text[match.start():match.end()], # Preserve original case
                        "category": category,
                        "severity": data["severity"],
                        "explanation": data["explanation"],
                        "index": match.start()
                    })

                if count > 0:
                    category_score += data["score_per_word"] * min(count, 3) # Cap per category word
            
            if category_score > 0:
                category_counts[category] = category_score
                total_risk += category_score

        # Normalize score to 0-100
        normalized_score = min(total_risk, 100)

        return {
            "detected_words": sorted(detected_words, key=lambda x: x['index']),
            "category_breakdown": category_counts,
            "keyword_risk_score": normalized_score
        }
