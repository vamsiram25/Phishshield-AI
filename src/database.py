import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path("phishshield.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snippet TEXT,
            label TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_scan(snippet, label, risk_score, risk_level):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO scan_history (snippet, label, risk_score, risk_level, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        snippet,
        label,
        risk_score,
        risk_level,
        datetime.utcnow().isoformat()
    ))

    conn.commit()
    conn.close()


def get_all_scans(limit: int = 100):
    """Return the most recent scans up to ``limit``.

    ``limit`` is provided to make testing easier and to avoid returning
    thousands of rows to the client.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM scan_history
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cur.fetchall()
    conn.close()

    return [dict(row) for row in rows]

def search_scans(query: str, limit: int = 100):
    """Return scans whose snippet contains ``query`` (case‑insensitive)."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT * FROM scan_history
        WHERE snippet LIKE ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (f"%{query}%", limit),
    )

    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_analytics():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM scan_history")
    total = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM scan_history WHERE label='phishing'")
    phishing = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM scan_history WHERE label='legitimate'")
    legitimate = cur.fetchone()[0]

    conn.close()

    return {
        "total_scans": total,
        "phishing_count": phishing,
        "legitimate_count": legitimate,
    }