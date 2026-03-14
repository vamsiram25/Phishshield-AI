from flask import Blueprint, render_template
from ..database import get_model_info

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/')
def index():
    model_info = get_model_info()
    return render_template('admin.html', model_info=model_info)
