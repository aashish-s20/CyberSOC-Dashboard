import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Security keys
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyber-soc-dashboard-super-secret-key-129038')
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        f'sqlite:///{os.path.join(BASE_DIR, "database", "cybersoc.db")}'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File storage paths
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    REPORT_FOLDER = os.path.join(BASE_DIR, 'reports')
    LOG_FOLDER = os.path.join(BASE_DIR, 'logs')
    
    # Ensure standard directories exist dynamically on config load
    @classmethod
    def init_app(cls, app):
        for folder in [cls.UPLOAD_FOLDER, cls.REPORT_FOLDER, cls.LOG_FOLDER, os.path.join(BASE_DIR, 'database')]:
            os.makedirs(folder, exist_ok=True)
