"""
PhishGuard — Scan Report Generator
Generates detailed HTML reports for individual URL and email scan results.
Can also export as printable HTML (user prints to PDF via browser).
"""

import json
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, abort, make_response
from flask_login import login_required, current_user

from app import db
from app.models.scan import URLScan, EmailScan
from app.ml.predictor import (predict_url, predict_email,
                               generate_url_reason, generate_email_reason)

report_scan_bp = Blueprint('scan_report', __name__, url_prefix='/report')


@report_scan_bp.route('/url/<int:scan_id>')
@login_required
def url_report(scan_id):
    scan = URLScan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    # Re-run prediction to get full reason (not stored in DB)
    result = predict_url(scan.url, scan.model_used or 'random_forest')
    reason = generate_url_reason(scan.url, result)
    return render_template('scan_report/url_report.html', scan=scan, result=result, reason=reason)


@report_scan_bp.route('/url/<int:scan_id>/print')
@login_required
def url_report_print(scan_id):
    scan = URLScan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    result = predict_url(scan.url, scan.model_used or 'random_forest')
    reason = generate_url_reason(scan.url, result)
    return render_template('scan_report/url_report_print.html', scan=scan, result=result, reason=reason)


@report_scan_bp.route('/email/<int:scan_id>')
@login_required
def email_report(scan_id):
    scan = EmailScan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    result = predict_email(scan.subject or '', scan.body or '', scan.sender or '')
    reason = generate_email_reason(scan.subject or '', scan.body or '', scan.sender or '', result)
    return render_template('scan_report/email_report.html', scan=scan, result=result, reason=reason)


@report_scan_bp.route('/email/<int:scan_id>/print')
@login_required
def email_report_print(scan_id):
    scan = EmailScan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    result = predict_email(scan.subject or '', scan.body or '', scan.sender or '')
    reason = generate_email_reason(scan.subject or '', scan.body or '', scan.sender or '', result)
    return render_template('scan_report/email_report_print.html', scan=scan, result=result, reason=reason)


@report_scan_bp.route('/url/live', methods=['POST'])
@login_required
def url_live_report():
    """Return reason JSON for a URL scan result inline (no DB needed)."""
    data   = request.get_json(silent=True) or {}
    url    = data.get('url', '').strip()
    model  = data.get('model', 'random_forest')
    if not url:
        return jsonify({'error': 'url required'}), 400
    result = predict_url(url, model)
    reason = generate_url_reason(url, result)
    return jsonify({**result, 'reason': reason})


@report_scan_bp.route('/email/live', methods=['POST'])
@login_required
def email_live_report():
    data   = request.get_json(silent=True) or {}
    result = predict_email(data.get('subject',''), data.get('body',''), data.get('sender',''))
    reason = generate_email_reason(data.get('subject',''), data.get('body',''), data.get('sender',''), result)
    return jsonify({**result, 'reason': reason})
