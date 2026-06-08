"""
Reports & Analytics routes.
"""

from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func

from app.models.scan import URLScan, EmailScan
from app.models.campaign import Campaign

reports_bp = Blueprint('reports', __name__)


@reports_bp.route('/')
@login_required
def index():
    # ── URL scan stats by day (last 30 days) ──────────────────────
    url_by_day = _scans_by_day(URLScan)
    email_by_day = _scans_by_day(EmailScan)

    # ── Overall totals ────────────────────────────────────────────
    url_total    = URLScan.query.count()
    url_phish    = URLScan.query.filter_by(prediction='phishing').count()
    email_total  = EmailScan.query.count()
    email_phish  = EmailScan.query.filter_by(prediction='phishing').count()
    camp_total   = Campaign.query.filter_by(user_id=current_user.id).count()
    camp_clicks  = sum(c.click_count for c in Campaign.query.filter_by(user_id=current_user.id).all())

    return render_template('reports/index.html',
                           url_by_day=url_by_day,
                           email_by_day=email_by_day,
                           url_total=url_total,
                           url_phish=url_phish,
                           email_total=email_total,
                           email_phish=email_phish,
                           camp_total=camp_total,
                           camp_clicks=camp_clicks)


@reports_bp.route('/chart-data')
@login_required
def chart_data():
    """JSON endpoint for Chart.js data."""
    url_by_day   = _scans_by_day(URLScan)
    email_by_day = _scans_by_day(EmailScan)

    return jsonify({
        'url_labels':   [r['date'] for r in url_by_day],
        'url_counts':   [r['count'] for r in url_by_day],
        'email_labels': [r['date'] for r in email_by_day],
        'email_counts': [r['count'] for r in email_by_day],
    })


def _scans_by_day(model, days=30):
    """Return list of {date, count} dicts for chart data."""
    from datetime import datetime, timedelta
    result = []
    for i in range(days - 1, -1, -1):
        day = (datetime.utcnow() - timedelta(days=i)).date()
        count = model.query.filter(
            func.date(model.scanned_at) == str(day)
        ).count()
        result.append({'date': str(day), 'count': count})
    return result
