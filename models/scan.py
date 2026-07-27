from datetime import datetime, timezone
from models.db import db

class NetworkScan(db.Model):
    __tablename__ = 'network_scans'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    results_json = db.Column(db.Text, nullable=True)  # Stores serialized full output for history retrieval

    # Relationships
    user = db.relationship('User', backref=db.backref('scans', lazy=True))
    port_results = db.relationship('PortResult', backref='scan', lazy=True, cascade="all, delete-orphan")
    dns_results = db.relationship('DNSResult', backref='scan', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<NetworkScan {self.scan_type} -> {self.target}>'

class PortResult(db.Model):
    __tablename__ = 'port_results'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('network_scans.id'), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    service = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return f'<PortResult {self.port}: {self.status}>'

class DNSResult(db.Model):
    __tablename__ = 'dns_results'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('network_scans.id'), nullable=False)
    record_type = db.Column(db.String(10), nullable=False)
    value = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<DNSResult {self.record_type} -> {self.value}>'
