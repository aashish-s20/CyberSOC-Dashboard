from datetime import datetime, timezone
from models.db import db

class LogFile(db.Model):
    __tablename__ = 'log_files'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    upload_time = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    total_events = db.Column(db.Integer, default=0)
    threat_count = db.Column(db.Integer, default=0)

    # Relationships
    user = db.relationship('User', backref=db.backref('log_files', lazy=True))
    events = db.relationship('LogEvent', backref='logfile', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<LogFile {self.filename} ({self.total_events} events, {self.threat_count} threats)>'

class LogEvent(db.Model):
    __tablename__ = 'log_events'

    id = db.Column(db.Integer, primary_key=True)
    logfile_id = db.Column(db.Integer, db.ForeignKey('log_files.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    source = db.Column(db.String(100), nullable=True)
    event_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False) # Critical, High, Medium, Low
    message = db.Column(db.Text, nullable=False)
    is_threat = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<LogEvent {self.severity}: {self.event_type}>'
