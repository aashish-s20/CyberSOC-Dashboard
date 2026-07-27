from datetime import datetime, timezone
from models.db import db

class ThreatIndicator(db.Model):
    __tablename__ = 'threat_indicators'
    
    id = db.Column(db.Integer, primary_key=True)
    ioc = db.Column(db.String(255), unique=True, nullable=False, index=True)
    ioc_type = db.Column(db.String(50), nullable=False) # 'IPv4 Address', 'Domain Name', 'URL', 'SHA-256 Hash'
    reputation_score = db.Column(db.Integer, nullable=False) # 0 to 100
    risk_level = db.Column(db.String(20), nullable=False) # 'Low', 'Medium', 'High', 'Critical'
    status = db.Column(db.String(20), nullable=False) # 'Safe', 'Suspicious', 'Malicious'
    category = db.Column(db.String(50), nullable=False) # 'Malware', 'Phishing', 'Botnet', 'Command & Control', 'Spam', 'Ransomware', 'Unknown'
    description = db.Column(db.String(500), nullable=True)
    detected_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

class ThreatIntelHistory(db.Model):
    __tablename__ = 'threat_intel_histories'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    ioc = db.Column(db.String(255), nullable=False)
    ioc_type = db.Column(db.String(50), nullable=False)
    reputation_score = db.Column(db.Integer, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    search_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('threat_searches', lazy=True, cascade='all, delete-orphan'))
