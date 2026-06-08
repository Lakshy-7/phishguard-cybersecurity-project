"""
Dashboard routes — main overview page.
"""

from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user

from app.models.scan import URLScan, EmailScan
from app.models.campaign import Campaign
from app.models.log import AuditLog
from app.ml.predictor import get_model_metadata

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@login_required
def index():
    # ── Stats ──────────────────────────────────────────────────────
    total_url_scans   = URLScan.query.count()
    total_email_scans = EmailScan.query.count()
    phishing_urls     = URLScan.query.filter_by(prediction='phishing').count()
    phishing_emails   = EmailScan.query.filter_by(prediction='phishing').count()
    active_campaigns  = Campaign.query.filter_by(status='active').count()
    total_campaigns   = Campaign.query.count()

    # ── Recent scans ───────────────────────────────────────────────
    recent_url_scans   = URLScan.query.order_by(URLScan.scanned_at.desc()).limit(5).all()
    recent_email_scans = EmailScan.query.order_by(EmailScan.scanned_at.desc()).limit(5).all()
    recent_logs        = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()

    # ── Detection rate ─────────────────────────────────────────────
    url_detection_rate   = round((phishing_urls / max(total_url_scans, 1)) * 100, 1)
    email_detection_rate = round((phishing_emails / max(total_email_scans, 1)) * 100, 1)

    # ── Model metadata ─────────────────────────────────────────────
    model_meta = get_model_metadata()

    stats = {
        'total_url_scans':      total_url_scans,
        'total_email_scans':    total_email_scans,
        'phishing_urls':        phishing_urls,
        'phishing_emails':      phishing_emails,
        'active_campaigns':     active_campaigns,
        'total_campaigns':      total_campaigns,
        'url_detection_rate':   url_detection_rate,
        'email_detection_rate': email_detection_rate,
    }

    return render_template(
        'dashboard/index.html',
        stats=stats,
        recent_url_scans=recent_url_scans,
        recent_email_scans=recent_email_scans,
        recent_logs=recent_logs,
        model_meta=model_meta
    )
