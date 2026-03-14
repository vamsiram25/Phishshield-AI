from ..database import get_db_connection, get_analytics_pro
from datetime import datetime, timedelta

class AnalyticsService:
    @staticmethod
    def get_dashboard_stats():
        return get_analytics_pro()

    @staticmethod
    def get_chart_data():
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Real dynamic date-based data
        labels = []
        phishing_data = []
        legit_data = []
        
        now = datetime.now()
        for i in range(6, -1, -1):
            date = (now - timedelta(days=i)).strftime('%Y-%m-%d')
            labels.append(date)
            
            cursor.execute("SELECT COUNT(*) FROM scans WHERE date(timestamp) = ? AND risk_level IN ('High', 'Critical')", (date,))
            phishing_data.append(cursor.fetchone()[0])
            
            cursor.execute("SELECT COUNT(*) FROM scans WHERE date(timestamp) = ? AND risk_level IN ('Low', 'Medium')", (date,))
            legit_data.append(cursor.fetchone()[0])
            
        conn.close()
        
        return {
            "labels": labels,
            "phishing": phishing_data,
            "legitimate": legit_data
        }

