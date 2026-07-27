import os
from flask import Flask
from flask_login import LoginManager
from config import Config
from models.db import db
from models.user import User
from models.scan import NetworkScan, PortResult, DNSResult
from models.monitor import MonitoringSession, CapturedPacket
from models.analyzer import LogFile, LogEvent
from models.vault import VaultFile, IntegrityCheck
from models.threat import ThreatIndicator, ThreatIntelHistory
from models.alert import Alert
from models.incident import Incident, IncidentNote
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
        seed_threat_indicators()
        seed_default_alerts()
        
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

def seed_threat_indicators():
    default_indicator = ThreatIndicator.query.first()
    if not default_indicator:
        indicators = [
            ThreatIndicator(
                ioc='198.51.100.45',
                ioc_type='IPv4 Address',
                reputation_score=15,
                risk_level='High',
                status='Malicious',
                category='Botnet',
                description='Active botnet node participating in distributed denial of service campaigns.'
            ),
            ThreatIndicator(
                ioc='malware-dropzone.net',
                ioc_type='Domain Name',
                reputation_score=8,
                risk_level='Critical',
                status='Malicious',
                category='Command & Control',
                description='Active command & control server hosting payloads for ransomware distribution.'
            ),
            ThreatIndicator(
                ioc='https://phishing-update.login-security.com/signin',
                ioc_type='URL',
                reputation_score=32,
                risk_level='Medium',
                status='Suspicious',
                category='Phishing',
                description='Credential harvesting landing page mimicking online financial portals.'
            ),
            ThreatIndicator(
                ioc='85155c4d62bb4be8d18471c261e4e4649a888c3a9d5d5a7d4a460bfae41f7142',
                ioc_type='SHA-256 Hash',
                reputation_score=0,
                risk_level='Critical',
                status='Malicious',
                category='Ransomware',
                description='SHA-256 signature associated with LockBit ransomware variant binary.'
            ),
            ThreatIndicator(
                ioc='8.8.8.8',
                ioc_type='IPv4 Address',
                reputation_score=100,
                risk_level='Low',
                status='Safe',
                category='Unknown',
                description='Google Public DNS server. Known benign resource.'
            )
        ]
        for ind in indicators:
            db.session.add(ind)
        db.session.commit()
        print("[DATABASE] Default Threat Indicators successfully seeded.")

def seed_default_alerts():
    default_alert = Alert.query.first()
    if not default_alert:
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        alerts = [
            Alert(
                timestamp=now - timedelta(hours=5),
                source_module='SecureVault',
                alert_type='Integrity Violation',
                severity='Critical',
                description='Integrity verification failed for secure file top_secret.txt. Checksum mismatch detected.',
                status='New'
            ),
            Alert(
                timestamp=now - timedelta(hours=10),
                source_module='Log Analyzer',
                alert_type='Threat Log Event',
                severity='High',
                description='Detected critical security event: SQL Injection attack attempt.',
                status='Acknowledged'
            ),
            Alert(
                timestamp=now - timedelta(hours=15),
                source_module='Network Scanner',
                alert_type='Open Port Detected',
                severity='Medium',
                description='Target target audit completed. Identified suspicious open ports: 23/telnet, 445/microsoft-ds.',
                status='Closed'
            ),
            Alert(
                timestamp=now - timedelta(hours=24),
                source_module='Threat Intelligence',
                alert_type='Malicious IOC Query',
                severity='High',
                description='Queried Malicious IP address 198.51.100.45. Reputation: 15/100. Category: Botnet.',
                status='New'
            )
        ]
        for a in alerts:
            db.session.add(a)
        db.session.commit()
        print("[DATABASE] Default Alerts successfully seeded.")

app = create_app()

if __name__ == '__main__':
    # Running Flask server on localhost port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)
