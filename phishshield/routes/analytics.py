from flask import Blueprint, render_template, current_app

analytics_bp = Blueprint('analytics', __name__)

@analytics_bp.route('/')
def index():
    chart_data = current_app.analytics_service.get_chart_data()
    return render_template('analytics.html', chart_data=chart_data)
