import sqlite3
import os
import json
from datetime import datetime
from flask import current_app

def get_db_connection():
    db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', 'phishshield.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snippet TEXT NOT NULL,
            label TEXT NOT NULL,
            risk_score REAL NOT NULL,
            risk_level TEXT NOT NULL,
            metadata TEXT,             -- JSON string for links & files
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def insert_scan(snippet, label, risk_score, risk_level, metadata=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (snippet, label, risk_score, risk_level, metadata)
        VALUES (?, ?, ?, ?, ?)
    ''', (snippet, label, risk_score, risk_level, json.dumps(metadata) if metadata else None))
    conn.commit()
    conn.close()

def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM scans")
    total = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'High'")
    high = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'Medium'")
    medium = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'Low'")
    low = cursor.fetchone()[0]
    
    cursor.execute("SELECT AVG(risk_score) FROM scans")
    avg_risk = cursor.fetchone()[0] or 0
    
    conn.close()
    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
        "avg_risk": round(avg_risk, 1),
        "threats": high
    }

def get_history(limit=50):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_scan(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def clear_history():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scans')
    conn.commit()
    conn.close()
