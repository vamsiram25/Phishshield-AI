from flask import Blueprint, render_template

scan_bp = Blueprint('scan', __name__)

@scan_bp.route('/')
def index():
    return render_template('scan.html')