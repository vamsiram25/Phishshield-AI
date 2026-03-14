import json

class ThreatEngine:
    def __init__(self, predictor, link_analyzer, attachment_analyzer):
        self.predictor = predictor
        self.link_analyzer = link_analyzer
        self.attachment_analyzer = attachment_analyzer

    def generate_report(self, email_text: str):
        # 1. ML Analysis
        ml_result = self.predictor.predict(email_text)
        ml_score = ml_result.get('risk_score', 0)

        # 2. Link Analysis
        link_result = self.link_analyzer.analyze(email_text)
        link_score = link_result.get('link_risk_score', 0)

        # 3. Attachment Analysis
        attachment_result = self.attachment_analyzer.analyze(email_text)
        attachment_score = attachment_result.get('attachment_risk_score', 0)

        # 4. Combined Weighted Score
        # ML (40%) + Link (35%) + Attachment (25%)
        final_score = (ml_score * 0.40) + (link_score * 0.35) + (attachment_score * 0.25)
        final_score = round(final_score, 2)

        # Determine Level
        if final_score > 85:
            threat_level = "Critical"
        elif final_score > 60:
            threat_level = "High"
        elif final_score > 30:
            threat_level = "Medium"
        else:
            threat_level = "Low"

        # Construct Full Report
        report = {
            "final_risk_score": final_score,
            "threat_level": threat_level,
            "ml_analysis": ml_result,
            "link_analysis": link_result,
            "attachment_analysis": attachment_result,
            "summary": self._generate_summary(threat_level, ml_result, link_result, attachment_result)
        }
        
        return report

    def _generate_summary(self, level, ml, lnk, att):
        if level == "Critical":
            return "Extreme risk detected. Multiple malicious vectors identified (AI Model, Infected Links, and Dangerous Attachments)."
        if level == "High":
            return "High probability of phishing. Significant red flags found in content and links."
        if level == "Medium":
            return "Suspicious indicators found. Proceed with caution."
        return "Minimal threat indicators detected. Email appears safe."
