import logging
from logging.handlers import RotatingFileHandler
from ..database import insert_scan

class LoggingService:
    def __init__(self, log_path):
        self.logger = logging.getLogger('phishshield')
        self.logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        file_handler = RotatingFileHandler(log_path, maxBytes=1024*1024, backupCount=5)
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)

    def log_scan(self, snippet, result):
        try:
            # Log to DB
            insert_scan(
                snippet=snippet[:100], # Truncate for DB
                label=result.get('label'),
                risk_score=result.get('risk_score'),
                risk_level=result.get('risk_level')
            )
            
            # Log to File
            self.logger.info(f"SCAN: Label={result.get('label')}, Score={result.get('risk_score')}, snippet={snippet[:50]}...")
        except Exception as e:
            self.logger.error(f"Logging error: {str(e)}")

    def log_error(self, message):
        self.logger.error(message)
