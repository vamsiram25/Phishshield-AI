from flask import Blueprint, render_template
from ..database import get_all_scans

history_bp = Blueprint('history', __name__)

@history_bp.route('/')
def index():
    scans = get_all_scans()
    return render_template('history.html', scans=scans)
