from datetime import datetime, timezone
from models.db import db

class MonitoringSession(db.Model):
    __tablename__ = 'monitoring_sessions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    interface = db.Column(db.String(100), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    end_time = db.Column(db.DateTime, nullable=True)
    total_packets = db.Column(db.Integer, default=0)

    # Relationships
    user = db.relationship('User', backref=db.backref('monitoring_sessions', lazy=True))
    packets = db.relationship('CapturedPacket', backref='session', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<MonitoringSession {self.interface} ({self.total_packets} packets)>'

class CapturedPacket(db.Model):
    __tablename__ = 'captured_packets'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('monitoring_sessions.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    source_ip = db.Column(db.String(50), nullable=False)
    destination_ip = db.Column(db.String(50), nullable=False)
    protocol = db.Column(db.String(20), nullable=False)
    length = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f'<CapturedPacket {self.protocol}: {self.source_ip} -> {self.destination_ip}>'
