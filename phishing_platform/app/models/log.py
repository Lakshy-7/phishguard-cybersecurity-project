"""
Audit log model for tracking all platform actions.
"""

from datetime import datetime
from app import db


class AuditLog(db.Model):
    """Security audit log for all significant platform events."""

    __tablename__ = 'audit_logs'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action     = db.Column(db.String(100), nullable=False)
    detail     = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    level      = db.Column(db.String(10), default='INFO')  # INFO|WARNING|ERROR
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f'<AuditLog {self.action} at {self.timestamp}>'

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'detail': self.detail,
            'ip_address': self.ip_address,
            'level': self.level,
            'timestamp': self.timestamp.isoformat()
        }

    @classmethod
    def log(cls, user_id, action, details='', ip_address=None, level='INFO'):
        """Convenience factory — create and commit an audit log entry."""
        entry = cls(
            user_id=user_id,
            action=action,
            detail=details,
            ip_address=ip_address,
            level=level,
        )
        db.session.add(entry)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
