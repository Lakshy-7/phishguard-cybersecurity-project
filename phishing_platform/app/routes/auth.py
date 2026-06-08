"""
Authentication routes: login, logout, register.
"""

from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from app import db
from app.models.user import User
from app.models.log import AuditLog

auth_bp = Blueprint('auth', __name__)


def _log(action: str, detail: str = '', level: str = 'INFO'):
    """Write an audit log entry."""
    uid = current_user.id if current_user.is_authenticated else None
    log = AuditLog(
        user_id=uid,
        action=action,
        detail=detail,
        ip_address=request.remote_addr,
        level=level
    )
    db.session.add(log)
    db.session.commit()


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Please enter both username and password.', 'danger')
            return render_template('auth/login.html')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            if not user.is_active:
                flash('Your account is disabled. Contact an administrator.', 'danger')
                return render_template('auth/login.html')

            login_user(user, remember=request.form.get('remember_me') == 'on')
            user.last_login = datetime.utcnow()
            db.session.commit()
            _log('LOGIN', f'User {username} logged in')

            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard.index'))
        else:
            _log('LOGIN_FAILED', f'Failed login for username: {username}', 'WARNING')
            flash('Invalid username or password.', 'danger')

    return render_template('auth/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    _log('LOGOUT', f'User {current_user.username} logged out')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username  = request.form.get('username', '').strip()
        email     = request.form.get('email', '').strip().lower()
        password  = request.form.get('password', '')
        confirm   = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()

        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if not email or '@' not in email:
            errors.append('Please enter a valid email address.')
        if not password or len(password) < 8:
            errors.append('Password must be at least 8 characters.')
        if password != confirm:
            errors.append('Passwords do not match.')
        if User.query.filter_by(username=username).first():
            errors.append('Username already taken.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('auth/register.html')

        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            full_name=full_name
        )
        db.session.add(new_user)
        db.session.commit()
        _log('REGISTER', f'New user registered: {username}')
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html')
