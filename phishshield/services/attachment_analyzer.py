import os
import re

class AttachmentAnalyzer:
    DANGEROUS_EXTENSIONS = {
        '.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.scr',
        '.docm', '.xlsm', '.pptm', '.zip', '.rar', '.7z'
    }
    
    HIGH_RISK_EXTENSIONS = {'.exe', '.scr', '.vbs', '.bat'}

    def analyze(self, content_text: str):
        # Simulation: In a real app we'd parse mime-parts. 
        # Here we scan text for common attachment triggers like "Attached: invoice.exe" 
        # or simulated inputs from the UI.
        
        # Look for simulated attachment metadata in text or common patterns
        attachments = re.findall(r'Attachment:\s*([\w\.-]+)', content_text, re.I)
        results = []
        total_risk = 0

        for file in attachments:
            name, ext = os.path.splitext(file.lower())
            risk = 0
            warnings = []
            
            # 1. Check dangerous extension
            if ext in self.DANGEROUS_EXTENSIONS:
                risk += 40
                warnings.append(f"Suspicious Extension ({ext})")
                if ext in self.HIGH_RISK_EXTENSIONS:
                    risk += 30
                    warnings.append("Highly Lethal File Type")

            # 2. Check for double extensions
            if name.count('.') > 0:
                risk += 30
                warnings.append("Double Extension Detected (.doc.exe)")

            # 3. Simulate sandbox check
            if "invoice" in name or "urgent" in name or "payment" in name:
                risk += 10
                warnings.append("Keyword Match: Financial Urgency")

            risk = min(risk, 100)
            total_risk += risk
            
            status = "Critical" if risk > 80 else "Dangerous" if risk > 40 else "Low Risk"
            
            results.append({
                "filename": file,
                "risk_score": risk,
                "status": status,
                "warnings": warnings
            })

        avg_risk = (total_risk / len(attachments)) if attachments else 0
        return {
            "attachments": results,
            "attachment_risk_score": round(avg_risk, 2),
            "attachment_count": len(attachments)
        }

import re # Needed for re.findall
