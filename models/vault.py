from datetime import datetime, timezone
from models.db import db

class VaultFile(db.Model):
    __tablename__ = 'vault_files'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False)
    upload_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    encryption_status = db.Column(db.String(50), default='Encrypted', nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    salt = db.Column(db.String(64), nullable=False)  # hex-encoded PBKDF2 salt
    iv = db.Column(db.String(32), nullable=False)    # hex-encoded AES IV
    password_hash = db.Column(db.String(255), nullable=False)  # hash to verify user entered password before decryption
    
    # Relationships
    user = db.relationship('User', backref=db.backref('vault_files', lazy=True, cascade='all, delete-orphan'))
    integrity_checks = db.relationship('IntegrityCheck', backref='vault_file', lazy=True, cascade='all, delete-orphan')

class IntegrityCheck(db.Model):
    __tablename__ = 'integrity_checks'
    
    id = db.Column(db.Integer, primary_key=True)
    vault_file_id = db.Column(db.Integer, db.ForeignKey('vault_files.id', ondelete='CASCADE'), nullable=False)
    check_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    checked_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    uploaded_filename = db.Column(db.String(255), nullable=False)
    computed_hash = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(50), nullable=False)  # 'Integrity Verified' or 'Integrity Failed'
    
    # Relationships
    checked_by = db.relationship('User', backref=db.backref('integrity_checks', lazy=True))
