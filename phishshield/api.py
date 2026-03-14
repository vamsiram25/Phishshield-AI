from flask import Blueprint, jsonify, request, current_app

api_v1_bp = Blueprint('api_v1', __name__)

@api_v1_bp.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    if not data or 'email_text' not in data:
        return jsonify({"error": "Missing email_text"}), 400
    
    email_text = data['email_text']
    
    # Use Pro Threat Engine
    report = current_app.threat_engine.generate_report(email_text)
    
    # Pro Logging (DB)
    from .database import insert_scan_pro
    insert_scan_pro(
        snippet=email_text[:100],
        label=report['threat_level'],
        risk_score=report['final_risk_score'],
        risk_level=report['threat_level'],
        links=report['link_analysis']['links'],
        attachments=report['attachment_analysis']['attachments'],
        report=report
    )
    
    # File Logging
    current_app.logger_service.logger.info(f"PRO SCAN: Level={report['threat_level']}, Score={report['final_risk_score']}")
    
    return jsonify(report)


@api_v1_bp.route('/history', methods=['GET'])
def get_history():
    from .database import get_all_scans
    scans = get_all_scans()
    return jsonify(scans)

@api_v1_bp.route('/stats', methods=['GET'])
def get_stats():
    stats = current_app.analytics_service.get_dashboard_stats()
    return jsonify(stats)
