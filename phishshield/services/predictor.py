import os
import joblib
import logging
from typing import Dict, Any

class PredictorService:
    def __init__(self):
        self.pipeline = None
        self.logger = logging.getLogger('phishshield.predictor')
        self._load_model()

    def _load_model(self):
        # Path to the unified model detector package
        base_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', '..', 'models')
        model_path = os.path.join(base_path, 'phishing_detector.pkl')

        try:
            if os.path.exists(model_path):
                payload = joblib.load(model_path)
                # The train.py saves a dict with 'best_pipeline'
                if isinstance(payload, dict):
                    self.pipeline = payload.get('best_pipeline')
                else:
                    self.pipeline = payload
                
                self.logger.info(f"Model package loaded from {model_path}")
            else:
                self.logger.warning(f"Model file not found at {model_path}")
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")

    def predict(self, email_text: str) -> Dict[str, Any]:
        if self.pipeline is None:
            return {
                "label": "Unknown",
                "risk_score": 0,
                "risk_level": "N/A",
                "indicators": [],
                "error": "Model not loaded"
            }

        try:
            # 1. Pipeline Prediction (includes Vectorizer)
            prediction = self.pipeline.predict([email_text])[0]
            label_name = "Phishing" if prediction == 1 or str(prediction).lower() == "phishing" else "Legitimate"
            
            # 2. Probability / Confidence
            if hasattr(self.pipeline, "predict_proba"):
                prob = self.pipeline.predict_proba([email_text])[0]
                risk_score = float(prob[1] * 100) if label_name == "Phishing" else float(prob[0] * 100)
            else:
                 risk_score = 85.0 if label_name == "Phishing" else 15.0
            
            # 3. Pattern Intelligence (NLP)
            indicators = self._scan_patterns(email_text)
            if indicators:
                risk_score = min(risk_score + (len(indicators) * 5), 100)

            if risk_score > 70:
                risk_level = "High"
            elif risk_score > 30:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            return {
                "label": label_name,
                "risk_score": round(risk_score, 2),
                "risk_level": risk_level,
                "indicators": indicators
            }
        except Exception as e:
            self.logger.error(f"Prediction error: {str(e)}")
            return {"error": str(e)}

    def _scan_patterns(self, text: str) -> list:
        text = text.lower()
        found = []
        
        patterns = {
            "Urgency/Action Required": ["urgent", "action required", "verify now", "immediately", "expire", "suspended"],
            "Financial/Bank Context": ["bank", "invoice", "payment", "transaction", "wire transfer", "billing"],
            "Security/Account Alert": ["security", "reset password", "unauthorized", "login attempt", "compromised"],
            "Generic Phishing Hooks": ["click here", "validation", "official notice", "update your account"]
        }
        
        for category, keywords in patterns.items():
            for word in keywords:
                if word in text:
                    found.append(category)
                    break 
                    
        return found

