from flask import Flask
from flask_cors import CORS
from .config import config
from .database import init_db
from .model import PhishModel
from .keyword_analyzer import KeywordAnalyzer

def create_app(config_name='default'):
    app = Flask(__name__)
    CORS(app)  # Enable CORS for the browser extension
    app.config.from_object(config[config_name])
    
    # Initialize DB
    with app.app_context():
        init_db()
    
    # Load Intelligence Engines
    app.phish_model = PhishModel()
    app.keyword_analyzer = KeywordAnalyzer()
    
    # Register consolidated routes
    from .routes import main_bp
    app.register_blueprint(main_bp)
    
    return app
