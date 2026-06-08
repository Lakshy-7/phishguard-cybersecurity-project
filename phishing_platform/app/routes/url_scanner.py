"""URL Phishing Scanner routes."""

import json
from flask import Blueprint, render_template, request, flash
from flask_login import login_required, current_user

from app import db
from app.models.scan import URLScan
from app.models.log import AuditLog
from app.ml.predictor import predict_url, generate_url_reason

url_bp = Blueprint('url', __name__)


@url_bp.route('/', methods=['GET', 'POST'])
@login_required
def scanner():
    result = None
    reason = None
    scan   = None
    url    = request.args.get('url', '').strip()  # support quick-scan from dashboard

    if request.method == 'POST':
        url   = request.form.get('url', '').strip()
        model = request.form.get('model', 'random_forest')

        if not url:
            flash('Please enter a URL to scan.', 'warning')
        elif len(url) > 2048:
            flash('URL is too long (max 2048 characters).', 'danger')
        else:
            try:
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
                    ip_address=request.remote_addr,
                )
                db.session.add(scan)
                db.session.commit()
                AuditLog.log(current_user.id, 'URL_SCAN',
                             f"{url[:100]} → {result['prediction']} (risk={result['risk_score']})",
                             request.remote_addr)
            except Exception as e:
                flash(f'Error scanning URL: {str(e)}', 'danger')
                AuditLog.log(current_user.id, 'URL_SCAN_ERROR', str(e),
                             request.remote_addr, level='ERROR')

    history = URLScan.query.filter_by(user_id=current_user.id)\
                           .order_by(URLScan.scanned_at.desc()).limit(20).all()
    return render_template('url_scanner/scanner.html',
                           result=result, reason=reason, scan=scan,
                           url=url, history=history)


@url_bp.route('/history')
@login_required
def history():
    page  = request.args.get('page', 1, type=int)
    scans = URLScan.query.filter_by(user_id=current_user.id)\
                         .order_by(URLScan.scanned_at.desc())\
                         .paginate(page=page, per_page=20)
    return render_template('url_scanner/history.html', scans=scans)
