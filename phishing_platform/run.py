"""
PhishGuard - Phishing Detection & Awareness Platform
Entry point: python run.py
"""

import os
import sys

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models.user import User, APIKey
from app.models.scan import URLScan, EmailScan
from app.models.campaign import Campaign, CampaignClick
from app.models.log import AuditLog

app = create_app()

def _run_migrations():
    """Add any missing columns to existing SQLite databases (safe to re-run)."""
    from sqlalchemy import text
    migrations = [
        # Table              Column          DDL type
        ('url_scans',   'indicators',   'TEXT'),
        ('url_scans',   'model_used',   'VARCHAR(50)'),
        ('users',       'full_name',    'VARCHAR(200)'),
        ('users',       'is_active',    'BOOLEAN DEFAULT 1'),
        ('users',       'last_login',   'DATETIME'),
        ('api_keys',    'use_count',    'INTEGER DEFAULT 0'),
    ]
    with db.engine.connect() as conn:
        for table, column, col_type in migrations:
            try:
                conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {col_type}'))
                conn.commit()
                print(f'  [migration] Added {table}.{column}')
            except Exception:
                pass   # Column already exists — silently skip


def initialize_database():
    """Create tables, run migrations, and seed default admin user."""
    with app.app_context():
        db.create_all()

        # ── Schema migrations (add new columns to existing DBs) ────
        _run_migrations()

        # Create default admin if not exists
        try:
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                from werkzeug.security import generate_password_hash
                admin = User(
                    username='admin',
                    email='admin@phishguard.local',
                    password_hash=generate_password_hash('admin123'),
                    is_admin=True,
                    full_name='Administrator'
                )
                db.session.add(admin)
                db.session.commit()
                print("[+] Default admin created: admin / admin123")
            else:
                print("[+] Admin user already exists.")
        except Exception:
            db.session.rollback()
            print("[+] Admin user already exists (skipped).")

        print("[+] Database initialized successfully.")

def train_models_if_needed():
    """Train ML models if they don't exist yet."""
    models_dir = os.path.join(os.path.dirname(__file__), 'app', 'ml', 'saved_models')
    url_model_path = os.path.join(models_dir, 'url_model.pkl')
    email_model_path = os.path.join(models_dir, 'email_model.pkl')

    if not os.path.exists(url_model_path) or not os.path.exists(email_model_path):
        print("[*] Training ML models (first run)...")
        from app.ml.train import train_all_models
        train_all_models()
        print("[+] Models trained and saved.")
    else:
        print("[+] ML models already trained.")

if __name__ == '__main__':
    print("=" * 55)
    print("  PhishGuard - Phishing Detection & Awareness Platform")
    print("=" * 55)

    initialize_database()
    train_models_if_needed()

    print("\n[+] Starting server at http://127.0.0.1:5000")
    print("[+] Login: admin / admin123")
    print("[+] Press CTRL+C to stop\n")

    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True,
        use_reloader=False  # Avoid double model training
    )
