"""
Campaign and click-tracking models for awareness simulations.
"""

from datetime import datetime
import secrets
from app import db


class Campaign(db.Model):
    """A phishing awareness simulation campaign."""

    __tablename__ = 'campaigns'

    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name          = db.Column(db.String(200), nullable=False)
    description   = db.Column(db.Text, nullable=True)
    template_type = db.Column(db.String(50), default='generic')  # generic|bank|it_support|hr
    status        = db.Column(db.String(20), default='draft')     # draft|active|completed
    target_count  = db.Column(db.Integer, default=0)
    sent_count    = db.Column(db.Integer, default=0)
    click_count   = db.Column(db.Integer, default=0)
    report_count  = db.Column(db.Integer, default=0)
    token         = db.Column(db.String(64), unique=True, default=lambda: secrets.token_urlsafe(32))
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at  = db.Column(db.DateTime, nullable=True)

    # Relationship
    clicks = db.relationship('CampaignClick', backref='campaign', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def click_rate(self):
        if self.sent_count == 0:
            return 0.0
        return round((self.click_count / self.sent_count) * 100, 1)

    @property
    def report_rate(self):
        if self.sent_count == 0:
            return 0.0
        return round((self.report_count / self.sent_count) * 100, 1)

    def __repr__(self):
        return f'<Campaign "{self.name}" status={self.status}>'

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'template_type': self.template_type,
            'status': self.status,
            'target_count': self.target_count,
            'sent_count': self.sent_count,
            'click_count': self.click_count,
            'report_count': self.report_count,
            'click_rate': self.click_rate,
            'report_rate': self.report_rate,
            'created_at': self.created_at.isoformat()
        }


class CampaignClick(db.Model):
    """Tracks when a simulation link is clicked (awareness only)."""

    __tablename__ = 'campaign_clicks'

    id           = db.Column(db.Integer, primary_key=True)
    campaign_id  = db.Column(db.Integer, db.ForeignKey('campaigns.id'), nullable=False)
    target_email = db.Column(db.String(200), nullable=True)
    ip_address   = db.Column(db.String(45), nullable=True)
    user_agent   = db.Column(db.String(500), nullable=True)
    clicked_at   = db.Column(db.DateTime, default=datetime.utcnow)
    educated     = db.Column(db.Boolean, default=False)  # Did user read the education page?

    def __repr__(self):
        return f'<CampaignClick campaign={self.campaign_id} at={self.clicked_at}>'
