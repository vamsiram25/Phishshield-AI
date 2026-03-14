from flask import Flask, request, jsonify
from src.predict import predict_email

app = Flask(__name__)

@app.route('/predict', methods=['POST'])
def predict():
    email = request.json.get('email')
    if not email:
        return jsonify({"error": "Email text is required"}), 400

    result = predict_email("models/phishing_detector.pkl", "data/preprocessed_data.pkl", email)
    return jsonify({"prediction": result})

if __name__ == "__main__":
    app.run(debug=True)
