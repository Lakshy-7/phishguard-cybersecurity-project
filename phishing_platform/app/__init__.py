"""
PhishGuard Flask Application Factory
"""

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()


def create_app():
    """Application factory pattern."""
    app = Flask(__name__, template_folder='templates', static_folder='static')

    # ── Configuration ──────────────────────────────────────────────
    basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'phishguard-secret-2024-change-in-prod')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'phishguard.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB upload limit

    # ── Extensions ─────────────────────────────────────────────────
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'

    # ── User loader ────────────────────────────────────────────────
    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ── Security headers ───────────────────────────────────────────
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

    # ── Register blueprints ────────────────────────────────────────
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.url_scanner import url_bp
    from app.routes.email_scanner import email_bp
    from app.routes.simulation import simulation_bp
    from app.routes.api import api_bp
    from app.routes.reports import reports_bp
    from app.routes.bulk_scan import bulk_bp
    from app.routes.settings import settings_bp
    from app.routes.domain_analyzer import domain_bp
    from app.routes.scan_report import report_scan_bp

    app.register_blueprint(auth_bp,        url_prefix='/auth')
    app.register_blueprint(dashboard_bp,   url_prefix='/')
    app.register_blueprint(url_bp,         url_prefix='/url')
    app.register_blueprint(email_bp,       url_prefix='/email')
    app.register_blueprint(simulation_bp,  url_prefix='/simulation')
    app.register_blueprint(api_bp,         url_prefix='/api')
    app.register_blueprint(reports_bp,     url_prefix='/reports')
    app.register_blueprint(bulk_bp,        url_prefix='/bulk')
    app.register_blueprint(settings_bp,    url_prefix='/settings')
    app.register_blueprint(domain_bp,      url_prefix='/domain')
    app.register_blueprint(report_scan_bp, url_prefix='/report')

    # Exempt JSON API endpoints from CSRF (they use X-API-Key header auth)
    csrf.exempt(api_bp)
    csrf.exempt(report_scan_bp)
    # Exempt only the JSON api endpoint within bulk, not the HTML form
    from app.routes.bulk_scan import api_bulk
    csrf.exempt(api_bulk)

    return app
