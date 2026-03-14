# PhishShield Web Browser Extension

This web browser extension seamlessly integrates the **PhishShield AI-Powered Phishing Intelligence** system directly into your browser, allowing you to scan web page content or manual text inputs in real-time.

## 🛠️ Installation Instructions

### Google Chrome / Microsoft Edge / Brave
1. Open your browser and navigate to the extensions page:
   - **Chrome**: `chrome://extensions/`
   - **Edge**: `edge://extensions/`
   - **Brave**: `brave://extensions/`
2. Enable **Developer mode** (usually a toggle switch in the top right corner).
3. Click the **"Load unpacked"** button.
4. Select this `extension` folder (`C:\Users\duvva\OneDrive\Desktop\6th sem\upgraded mini project\upgraded mini project\phishing-detection (2)\phishing-detection\extension`).
5. The extension will now appear in your toolbar (you may need to click the puzzle piece icon to pin it).

## 🚀 Usage

1. Ensure your PhishShield backend server is running:
   ```bash
   python run.py
   ```
   *(Running locally on `http://127.0.0.1:5001` or `5000`)* 
   *Note: Our script uses `5001` as configured in `run.py`.*

2. Click the **🛡️ PhishShield** icon in your browser toolbar.
3. You can choose to:
   - **SCAN PAGE CONTEXT:** Automatically extracts the visible text on the active webpage and sends it to the AI for phishing detection.
   - **MANUAL INSPECTION:** Paste a suspicious URL, email snippet, or paragraph into the text box and click **ANALYZE TEXT**.
4. View the real-time AI heuristics, risk classification, and link analytics directly in the gorgeous Cyber-Glass UI popup.

## ⚡ Technical Architecture
- **Manifest V3** compliant.
- **RESTful Integration:** Communicates locally via secure fetch API with `http://127.0.0.1:5001/scan`.
- **CORS Support:** The backend logic has been updated with `Flask-CORS` to allow requests originating tightly from the browser instance.
