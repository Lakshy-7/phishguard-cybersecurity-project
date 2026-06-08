"""
REST API routes for PhishGuard.

All endpoints return JSON. Authentication uses session cookie.
"""

import json
from functools import wraps
from flask import Blueprint, jsonify, request, g
from flask_login import current_user, login_required

from app import db
from app.models.scan import URLScan, EmailScan
from app.models.campaign import Campaign
from app.ml.predictor import predict_url, predict_email, get_model_metadata

api_bp = Blueprint('api', __name__)


from app.models.user import APIKey

def api_login_required(f):
    """Decorator: accepts session auth OR X-API-Key header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Try session auth first
        if current_user.is_authenticated:
            return f(*args, **kwargs)
        # Try API key
        api_key_raw = request.headers.get('X-API-Key', '').strip()
        if api_key_raw:
            key_obj = APIKey.verify(api_key_raw)
            if key_obj:
                from flask_login import login_user
                login_user(key_obj.user, remember=False)
                result = f(*args, **kwargs)
                return result
        return jsonify({'error': 'Authentication required. Use session login or X-API-Key header.', 'status': 401}), 401
    return decorated


# ── Health check ───────────────────────────────────────────────────────────────

@api_bp.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'PhishGuard API', 'version': '1.0'})


# ── URL scan API ───────────────────────────────────────────────────────────────

@api_bp.route('/scan/url', methods=['POST'])
@api_login_required
def api_scan_url():
    """
    POST /api/scan/url
    Body: {"url": "http://example.com", "model": "random_forest"}
    Returns: scan result JSON
    """
    data  = request.get_json(silent=True) or {}
    url   = (data.get('url') or '').strip()
    model = data.get('model', 'random_forest')

    if not url:
        return jsonify({'error': 'url field is required'}), 400
    if len(url) > 2048:
        return jsonify({'error': 'URL too long (max 2048 chars)'}), 400
    if model not in ('random_forest', 'logistic_regression', 'gradient_boosting'):
        model = 'random_forest'

    try:
        from app.ml.predictor import generate_url_reason
        result = predict_url(url, model=model)
        reason = generate_url_reason(url, result)
        scan = URLScan(
            user_id=current_user.id,
            url=url,
            prediction=result['prediction'],
            confidence=result['confidence'],
            risk_score=result['risk_score'],
            model_used=result['model_used'],
            features_json=json.dumps(result.get('features', {})),
            indicators=json.dumps(result.get('indicators', [])),
            ip_address=request.remote_addr
        )
        db.session.add(scan)
        db.session.commit()
        result['scan_id'] = scan.id
        result['reason']  = reason
        return jsonify({'status': 'ok', 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Email scan API ─────────────────────────────────────────────────────────────

@api_bp.route('/scan/email', methods=['POST'])
@api_login_required
def api_scan_email():
    """
    POST /api/scan/email
    Body: {"subject": "...", "body": "...", "sender": "..."}
    Returns: scan result JSON
    """
    data    = request.get_json(silent=True) or {}
    subject = (data.get('subject') or '').strip()
    body    = (data.get('body') or '').strip()
    sender  = (data.get('sender') or '').strip()

    if not subject and not body:
        return jsonify({'error': 'At least subject or body is required'}), 400

    try:
        result = predict_email(subject, body, sender)
        scan = EmailScan(
            user_id=current_user.id,
            subject=subject[:500],
            body=body[:10000],
            sender=sender[:200],
            prediction=result['prediction'],
            confidence=result['confidence'],
            risk_score=result['risk_score'],
            indicators=json.dumps(result.get('indicators', []))
        )
        db.session.add(scan)
        db.session.commit()
        result['scan_id'] = scan.id
        return jsonify({'status': 'ok', 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Stats API ──────────────────────────────────────────────────────────────────

@api_bp.route('/stats')
@api_login_required
def api_stats():
    """GET /api/stats — platform-wide detection statistics."""
    url_total     = URLScan.query.count()
    url_phishing  = URLScan.query.filter_by(prediction='phishing').count()
    email_total   = EmailScan.query.count()
    email_phishing= EmailScan.query.filter_by(prediction='phishing').count()

    return jsonify({
        'url_scans':         url_total,
        'url_phishing':      url_phishing,
        'url_legitimate':    url_total - url_phishing,
        'email_scans':       email_total,
        'email_phishing':    email_phishing,
        'email_legitimate':  email_total - email_phishing,
        'model_info':        get_model_metadata()
    })


# ── History API ────────────────────────────────────────────────────────────────

@api_bp.route('/history/url')
@api_login_required
def api_url_history():
    limit = min(int(request.args.get('limit', 20)), 100)
    scans = URLScan.query.filter_by(user_id=current_user.id)\
                         .order_by(URLScan.scanned_at.desc()).limit(limit).all()
    return jsonify({'status': 'ok', 'scans': [s.to_dict() for s in scans]})


@api_bp.route('/history/email')
@api_login_required
def api_email_history():
    limit = min(int(request.args.get('limit', 20)), 100)
    scans = EmailScan.query.filter_by(user_id=current_user.id)\
                           .order_by(EmailScan.scanned_at.desc()).limit(limit).all()
    return jsonify({'status': 'ok', 'scans': [s.to_dict() for s in scans]})
