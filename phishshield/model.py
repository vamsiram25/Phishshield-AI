import os
import joblib
import logging

class PhishModel:
    def __init__(self):
        self.pipeline = None
        self.logger = logging.getLogger('phishshield.model')
        self._load_model()

    def _load_model(self):
        base_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', 'models')
        model_path = os.path.join(base_path, 'phishing_detector.pkl')

        try:
            if os.path.exists(model_path):
                payload = joblib.load(model_path)
                self.pipeline = payload.get('best_pipeline') if isinstance(payload, dict) else payload
                self.logger.info("ML model loaded successfully.")
            else:
                self.logger.warning(f"Model file not found at {model_path}")
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")

    def predict(self, text):
        if not self.pipeline:
            return {"label": "Unknown", "score": 0}
        
        prediction = self.pipeline.predict([text])[0]
        label = "Phishing" if prediction == 1 or str(prediction).lower() == "phishing" else "Legitimate"
        
        if hasattr(self.pipeline, "predict_proba"):
            try:
                prob = self.pipeline.predict_proba([text])[0]
                score = float(prob[1] * 100) if label == "Phishing" else float(prob[0] * 100)
            except AttributeError:
                score = 85.0 if label == "Phishing" else 15.0
        else:
            score = 85.0 if label == "Phishing" else 15.0
            
        return {"label": label, "score": round(score, 2)}
