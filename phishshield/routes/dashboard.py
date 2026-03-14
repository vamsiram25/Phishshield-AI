from flask import Blueprint, render_template, current_app

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
def index():
    stats = current_app.analytics_service.get_dashboard_stats()
    return render_template('dashboard.html', stats=stats)
