"""
User database model with Flask-Login integration.
"""

from datetime import datetime
from flask_login import UserMixin
from app import db


class User(UserMixin, db.Model):
    """Authenticated user of the PhishGuard platform."""

    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name     = db.Column(db.String(120), default='')
    is_admin      = db.Column(db.Boolean, default=False)
    is_active     = db.Column(db.Boolean, default=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    last_login    = db.Column(db.DateTime, nullable=True)

    # Relationships
    url_scans     = db.relationship('URLScan', backref='user', lazy='dynamic')
    email_scans   = db.relationship('EmailScan', backref='user', lazy='dynamic')
    campaigns     = db.relationship('Campaign', backref='creator', lazy='dynamic')
    logs          = db.relationship('AuditLog', backref='user', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.username}>'

    def get_id(self):
        return str(self.id)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat()
        }


class APIKey(db.Model):
    """API key for programmatic access to PhishGuard REST API."""

    __tablename__ = 'api_keys'

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    key_hash    = db.Column(db.String(256), unique=True, nullable=False)
    key_prefix  = db.Column(db.String(12), nullable=False)   # first 8 chars shown to user
    name        = db.Column(db.String(100), default='My API Key')
    is_active   = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    last_used   = db.Column(db.DateTime, nullable=True)
    use_count   = db.Column(db.Integer, default=0)

    user = db.relationship('User', backref=db.backref('api_keys', lazy='dynamic'))

    @staticmethod
    def generate():
        """Return (raw_key, key_hash, prefix). Store hash, show raw once."""
        import secrets, hashlib
        raw    = 'pg_' + secrets.token_hex(24)
        hashed = hashlib.sha256(raw.encode()).hexdigest()
        prefix = raw[:12]
        return raw, hashed, prefix

    @staticmethod
    def verify(raw_key: str):
        """Return APIKey object if key is valid and active, else None."""
        import hashlib
        hashed = hashlib.sha256(raw_key.encode()).hexdigest()
        key = APIKey.query.filter_by(key_hash=hashed, is_active=True).first()
        if key:
            from datetime import datetime
            key.last_used = datetime.utcnow()
            key.use_count += 1
            db.session.commit()
        return key

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'key_prefix': self.key_prefix + '...',
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'use_count': self.use_count,
        }
