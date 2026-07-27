import os
from flask import Flask
from flask_login import LoginManager
from config import Config
from models.db import db
from models.user import User
from models.scan import NetworkScan, PortResult, DNSResult
from models.monitor import MonitoringSession, CapturedPacket
from models.analyzer import LogFile, LogEvent
from routes.auth import auth_bp
from routes.main import main_bp
from routes.errors import errors_bp


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize directory structure dynamically from configuration
    Config.init_app(app)
    
    # Initialize database
    db.init_app(app)
    
    # Setup login manager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please authenticate to access the CyberSOC console.'
    login_manager.login_message_category = 'error'
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))
        
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(errors_bp)
    
    # Initialize database tables and seed default user inside application context
    with app.app_context():
        db.create_all()
        seed_default_user()
        
    return app

def seed_default_user():
    # Verify if manager user already exists
    default_manager = User.query.filter_by(username='manager').first()
    if not default_manager:
        manager = User(
            username='manager',
            email='manager@cybersoc.lan',
            role='SOC Manager',
            status='Active'
        )
        manager.set_password('Manager@123')
        db.session.add(manager)
        db.session.commit()
        print("[DATABASE] Default SOC Manager account successfully seeded.")

app = create_app()

if __name__ == '__main__':
    # Running Flask server on localhost port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)
