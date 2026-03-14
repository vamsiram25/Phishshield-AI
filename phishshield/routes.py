import os
import json
import io
import pandas as pd
from flask import Blueprint, render_template, request, jsonify, current_app, send_file
from werkzeug.utils import secure_filename
from .database import get_stats, get_history, insert_scan, get_scan, clear_history
from .utils import analyze_links, analyze_attachment, calculate_final_risk, generate_analysis_summary

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def dashboard():
    stats = get_stats()
    recent = get_history(limit=5)
    return render_template('dashboard.html', stats=stats, recent=recent)

@main_bp.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        email_text = request.form.get('email_text', '')
        file = request.files.get('attachment')
        
        # 1. ML Analysis
        ml_result = current_app.phish_model.predict(email_text)
        
        # 2. Link Analysis
        link_result = analyze_links(email_text)
        
        # 3. Keyword Intelligence
        keyword_result = current_app.keyword_analyzer.analyze(email_text)
        
        # 4. Attachment Analysis
        attach_result = {"score": 0, "warnings": []}
        if file and file.filename:
            filename = secure_filename(file.filename)
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)
            attach_result = analyze_attachment(filename, file_size)
            
        # 5. Final Risk
        final_risk = calculate_final_risk(
            ml_result['score'], 
            link_result['score'], 
            attach_result['score'],
            keyword_result['keyword_risk_score']
        )
        
        # 6. Generate Tactical Explanation
        summary = generate_analysis_summary(ml_result, link_result, keyword_result, attach_result, final_risk)
        
        # 7. Store in DB
        metadata = {
            "links": link_result['links'],
            "attachment": attach_result,
            "keywords": keyword_result['detected_words'],
            "summary": summary
        }
        insert_scan(
            snippet=email_text[:100],
            label=ml_result['label'] if final_risk['score'] < 50 else "Phishing",
            risk_score=final_risk['score'],
            risk_level=final_risk['level'],
            metadata=metadata
        )
        
        return jsonify({
            "status": "success",
            "prediction": ml_result,
            "links": link_result,
            "attachment": attach_result,
            "keywords": keyword_result,
            "final_risk": final_risk,
            "summary": summary
        })
        
    return render_template('scan.html')

@main_bp.route('/history')
def history():
    scans = get_history()
    return render_template('history.html', scans=scans)

@main_bp.route('/history/<int:scan_id>')
def history_detail(scan_id):
    scan_data = get_scan(scan_id)
    if not scan_data:
        return "Scan not found", 404
    
    # Parse metadata JSON
    data = dict(scan_data)
    if data['metadata']:
        data['metadata'] = json.loads(data['metadata'])
    
    return jsonify(data)

@main_bp.route('/history/clear', methods=['POST'])
def clear_all_history():
    clear_history()
    return jsonify({"status": "success"})

@main_bp.route('/history/export', methods=['GET'])
def export_history():
    scans = get_history(limit=10000)
    if not scans:
        return "No data to export", 404
        
    df = pd.DataFrame(scans)
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Threat History')
    
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='threat_history.xlsx'
    )
