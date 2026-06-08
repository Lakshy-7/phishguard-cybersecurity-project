"""
User settings: profile, password change, API key management.
"""

import hashlib
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from app import db
from app.models.user import APIKey
from app.models.log import AuditLog

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')


@settings_bp.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        action = request.form.get('action')

        # ── Update profile ─────────────────────────────────────────
        if action == 'update_profile':
            full_name = request.form.get('full_name', '').strip()
            email     = request.form.get('email', '').strip()
            if not email:
                flash('Email is required.', 'danger')
            else:
                current_user.full_name = full_name
                current_user.email     = email
                db.session.commit()
                AuditLog.log(current_user.id, 'profile_update', 'User updated profile')
                flash('Profile updated successfully.', 'success')

        # ── Change password ────────────────────────────────────────
        elif action == 'change_password':
            current_pw  = request.form.get('current_password', '')
            new_pw      = request.form.get('new_password', '')
            confirm_pw  = request.form.get('confirm_password', '')

            if not check_password_hash(current_user.password_hash, current_pw):
                flash('Current password is incorrect.', 'danger')
            elif len(new_pw) < 8:
                flash('New password must be at least 8 characters.', 'danger')
            elif new_pw != confirm_pw:
                flash('New passwords do not match.', 'danger')
            else:
                current_user.password_hash = generate_password_hash(new_pw)
                db.session.commit()
                AuditLog.log(current_user.id, 'password_change', 'User changed password')
                flash('Password changed successfully.', 'success')

        return redirect(url_for('settings.index'))

    api_keys = APIKey.query.filter_by(user_id=current_user.id, is_active=True)\
                           .order_by(APIKey.created_at.desc()).all()
    return render_template('settings/index.html', api_keys=api_keys)


@settings_bp.route('/api-keys/create', methods=['POST'])
@login_required
def create_api_key():
    name = request.form.get('key_name', 'My API Key').strip() or 'My API Key'
    # Max 5 active keys per user
    count = APIKey.query.filter_by(user_id=current_user.id, is_active=True).count()
    if count >= 5:
        flash('Maximum 5 API keys allowed. Delete an existing key first.', 'danger')
        return redirect(url_for('settings.index'))

    raw, hashed, prefix = APIKey.generate()
    key = APIKey(user_id=current_user.id, key_hash=hashed,
                 key_prefix=prefix, name=name)
    db.session.add(key)
    db.session.commit()
    AuditLog.log(current_user.id, 'api_key_created', f'Created API key: {name}')
    # Pass raw key once via flash — never stored
    flash(f'API key created. Copy it now — it will not be shown again:\n{raw}', 'api_key')
    return redirect(url_for('settings.index'))


@settings_bp.route('/api-keys/<int:key_id>/delete', methods=['POST'])
@login_required
def delete_api_key(key_id):
    key = APIKey.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    key.is_active = False
    db.session.commit()
    AuditLog.log(current_user.id, 'api_key_deleted', f'Deleted API key: {key.name}')
    flash(f'API key "{key.name}" revoked.', 'success')
    return redirect(url_for('settings.index'))
