# 🛡️ PHISHSHIELD: AI-Powered Phishing Intelligence

**PHISHSHIELD** is a professional-grade cybersecurity platform designed to perform multi-vector analysis on email threats and web pages. It combines Machine Learning, Linguistic Intelligence, Link/Attachment Forensics, and a dedicated **Browser Extension** into a stunning "Cyber-Glass" interface.

Developed by **Vamsi** (along with Seshu and Jayalakshmi).

---

## 🌟 Key Features

- **`Keyword Intelligence Engine`**: Recursive highlighting of tactical phishing vectors with expert security explanations.
- **`Vector Prediction Core`**: TF-IDF + Logistic Regression ML model for high-confidence classification.
- **`Link Forensics`**: Deep inspection of URLs for IP-based domains, suspicious TLDs (.xyz, .ru), and obfuscated shorteners.
- **`Attachment Sandbox`**: Static analysis of extensions, double-extensions, and anomalous file metadata.
- **`Threat Archive`**: Persistent SQLite storage with detailed forensic reports for every scan.
- **`PhishShield Browser Extension`**: Scan active web pages and manual text instantly from your browser toolbar via Manifest V3.

---

## 🎨 Premium UI Aesthetics

- **Cyber-Glass UI**: A modern, dark-themed interface with glassmorphism and neon accents.
- **Security View Toggle**: Switch between raw source data and a highlighted diagnostic view.
- **Animated Risk Meter**: Instant visual feedback on the consolidated threat level.

---

## 🛠️ Step-by-Step Installation Guide

Follow these instructions to set up PhishShield on your local machine.

### Part 1: Setting up the Local Backend Server

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/phishshield.git
   cd phishshield
   ```

2. **Create a Virtual Environment (Optional but Recommended)**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements/requirements.txt
   pip install flask-cors  # Required for browser extension communication
   ```

4. **Initialize the Intelligence Core**
   ```bash
   python run.py
   ```
   > The server should now be running locally on `http://127.0.0.1:5001`.

5. **Access the Portal**
   Open `http://127.0.0.1:5001` in your secure browser to view the main dashboard!

### Part 2: Installing the Browser Extension (Chrome/Edge/Brave)

To integrate PhishShield directly into your browser:

1. Open your Chromium-based browser and navigate to the extensions page:
   - **Chrome**: `chrome://extensions/`
   - **Edge**: `edge://extensions/`
   - **Brave**: `brave://extensions/`
2. Enable **Developer mode** (usually a toggle switch in the top right corner).
3. Click the **"Load unpacked"** button.
4. Select the `extension` folder located inside this repository.
5. The **🛡️ PhishShield** extension will now appear in your toolbar! Pin it for quick access.
6. Make sure your Python backend server (`python run.py`) is running. Click the extension to **Scan Page Context** or perform **Manual Inspection**.

---

## 🏗️ Technical Architecture

```text
phishshield/
├── extension/          # Browser Extension (Manifest V3, HTML, CSS, JS)
├── phishshield/        # Main Flask Application
│   ├── __init__.py     # App Factory & Engine Loading (CORS enabled)
│   ├── routes.py       # Logic Hub (Dashboard, Scan, History)
│   ├── database.py     # Persistence Layer (SQLite)
│   ├── model.py        # ML Intelligence (Scikit-learn)
│   ├── keyword_analyzer.py # Linguistic Engine
│   ├── utils.py        # Link & Attachment Forensics
│   ├── static/         # Premium Assets, CSS, Logos
│   └── templates/      # Jinja2 Layouts
├── data/               # Datasets and Intelligence Feeds
├── models/             # Pre-trained ML Models
├── requirements/       # Dependency specifications
└── run.py              # Entry Component
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/yourusername/phishshield/issues) if you want to contribute.

## 📜 Copyright & Usage Disclaimer

© 2026 Developed by Vamsi, Seshu, JayaLakshmi. 
All rights reserved.

> **Disclaimer:** This project is an advanced cybersecurity diagnostic tool. Unauthorized redistribution or commercial use is prohibited without permission.
