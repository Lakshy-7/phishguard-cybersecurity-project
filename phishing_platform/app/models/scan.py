"""
Scan result models for URL and Email phishing detection.
"""

from datetime import datetime
from app import db


class URLScan(db.Model):
    """Record of a URL phishing scan."""

    __tablename__ = 'url_scans'

    id               = db.Column(db.Integer, primary_key=True)
    user_id          = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    url              = db.Column(db.Text, nullable=False)
    prediction       = db.Column(db.String(20), nullable=False)
    confidence       = db.Column(db.Float, nullable=False)
    model_used       = db.Column(db.String(50), default='random_forest')
    risk_score       = db.Column(db.Float, default=0.0)
    features_json    = db.Column(db.Text, nullable=True)
    indicators       = db.Column(db.Text, nullable=True)   # JSON list of warning signs
    ip_address       = db.Column(db.String(45), nullable=True)
    scanned_at       = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<URLScan {self.url[:40]} → {self.prediction}>'

    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'prediction': self.prediction,
            'confidence': round(self.confidence * 100, 2),
            'risk_score': self.risk_score,
            'model_used': self.model_used,
            'scanned_at': self.scanned_at.isoformat()
        }


class EmailScan(db.Model):
    """Record of an email phishing scan."""

    __tablename__ = 'email_scans'

    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    subject       = db.Column(db.String(500), nullable=False)
    body          = db.Column(db.Text, nullable=False)
    sender        = db.Column(db.String(200), nullable=True)
    prediction    = db.Column(db.String(20), nullable=False)   # 'phishing' | 'legitimate'
    confidence    = db.Column(db.Float, nullable=False)
    risk_score    = db.Column(db.Float, default=0.0)
    indicators    = db.Column(db.Text, nullable=True)          # JSON list of warning signs
    scanned_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<EmailScan "{self.subject[:40]}" → {self.prediction}>'

    def to_dict(self):
        import json
        return {
            'id': self.id,
            'subject': self.subject,
            'sender': self.sender,
            'prediction': self.prediction,
            'confidence': round(self.confidence * 100, 2),
            'risk_score': self.risk_score,
            'indicators': json.loads(self.indicators) if self.indicators else [],
            'scanned_at': self.scanned_at.isoformat()
        }
