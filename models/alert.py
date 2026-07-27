from datetime import datetime, timezone
from models.db import db

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    source_module = db.Column(db.String(50), nullable=False) # 'Network Scanner', 'Network Monitor', 'Log Analyzer', 'Threat Intelligence', 'SecureVault'
    alert_type = db.Column(db.String(100), nullable=False)   # e.g., 'Open Port Detected', 'Threat Log Event'
    severity = db.Column(db.String(20), nullable=False)      # 'Critical', 'High', 'Medium', 'Low'
    description = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='New', nullable=False) # 'New', 'Acknowledged', 'Closed'
