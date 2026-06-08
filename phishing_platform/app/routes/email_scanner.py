"""Email Phishing Scanner routes."""

import json
from flask import Blueprint, render_template, request, flash
from flask_login import login_required, current_user

from app import db
from app.models.scan import EmailScan
from app.models.log import AuditLog
from app.ml.predictor import predict_email, generate_email_reason

email_bp = Blueprint('email', __name__)


@email_bp.route('/', methods=['GET', 'POST'])
@login_required
def scanner():
    result  = None
    reason  = None
    scan    = None
    subject = ''
    body    = ''
    sender  = ''

    if request.method == 'POST':
        subject = request.form.get('subject', '').strip()
        body    = request.form.get('body', '').strip()
        sender  = request.form.get('sender', '').strip()

        if not body and not subject:
            flash('Please enter at least a subject or email body.', 'warning')
        else:
            try:
                result = predict_email(subject, body, sender)
                reason = generate_email_reason(subject, body, sender, result)

                scan = EmailScan(
                    user_id=current_user.id,
                    subject=subject[:500],
                    body=body,
                    sender=sender[:200],
                    prediction=result['prediction'],
                    confidence=result['confidence'],
                    risk_score=result['risk_score'],
                    indicators=json.dumps(result.get('indicators', [])),
                )
                db.session.add(scan)
                db.session.commit()
                AuditLog.log(current_user.id, 'EMAIL_SCAN',
                             f"Subject: {subject[:80]} → {result['prediction']} (risk={result['risk_score']})",
                             request.remote_addr)
            except Exception as e:
                flash(f'Error scanning email: {str(e)}', 'danger')

    history = EmailScan.query.filter_by(user_id=current_user.id)\
                             .order_by(EmailScan.scanned_at.desc()).limit(10).all()
    return render_template('email_scanner/scanner.html',
                           result=result, reason=reason, scan=scan,
                           subject=subject, body=body, sender=sender,
                           history=history)


@email_bp.route('/history')
@login_required
def history():
    page  = request.args.get('page', 1, type=int)
    scans = EmailScan.query.filter_by(user_id=current_user.id)\
                           .order_by(EmailScan.scanned_at.desc())\
                           .paginate(page=page, per_page=20)
    return render_template('email_scanner/history.html', scans=scans)
