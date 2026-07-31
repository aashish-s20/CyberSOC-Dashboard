from datetime import datetime, timezone
from models.db import db

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    username = db.Column(db.String(100), nullable=True)
    user_role = db.Column(db.String(100), nullable=True)
    module = db.Column(db.String(100), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), nullable=True)
    details = db.Column(db.String(500), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
