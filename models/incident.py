from datetime import datetime, timezone
from models.db import db

class Incident(db.Model):
    __tablename__ = 'incidents'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    related_alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id', ondelete='SET NULL'), nullable=True)
    assigned_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    priority = db.Column(db.String(20), nullable=False)      # 'Critical', 'High', 'Medium', 'Low'
    status = db.Column(db.String(20), default='Open', nullable=False) # 'Open', 'In Progress', 'Resolved', 'Closed'
    created_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    closed_date = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    related_alert = db.relationship('Alert', backref=db.backref('incidents', lazy=True))
    assigned_user = db.relationship('User', backref=db.backref('assigned_incidents', lazy=True))
    notes = db.relationship('IncidentNote', backref='incident', lazy=True, cascade='all, delete-orphan')

class IncidentNote(db.Model):
    __tablename__ = 'incident_notes'
    
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    note = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('incident_notes', lazy=True))
