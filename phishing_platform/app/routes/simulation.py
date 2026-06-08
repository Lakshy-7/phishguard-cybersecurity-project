"""
Phishing Awareness Simulation Module.

EDUCATIONAL USE ONLY — No real credentials are collected.
All pages display educational content after click tracking.
"""

from datetime import datetime
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, abort)
from flask_login import login_required, current_user

from app import db
from app.models.campaign import Campaign, CampaignClick
from app.models.log import AuditLog

simulation_bp = Blueprint('simulation', __name__)


# ── Available simulation templates ────────────────────────────────────────────
TEMPLATES = {
    'generic':    {'name': 'Generic Credential Harvest', 'icon': 'shield-exclamation'},
    'bank':       {'name': 'Bank Security Alert',        'icon': 'bank'},
    'it_support': {'name': 'IT Support Password Reset',  'icon': 'pc-display'},
    'hr':         {'name': 'HR Benefits Update',         'icon': 'people'},
    'prize':      {'name': 'Prize Winner Notification',  'icon': 'gift'},
}


def _log(action, detail='', level='INFO'):
    uid = current_user.id if current_user.is_authenticated else None
    log = AuditLog(user_id=uid, action=action, detail=detail,
                   ip_address=request.remote_addr, level=level)
    db.session.add(log)
    db.session.commit()


# ── Campaign management ────────────────────────────────────────────────────────

@simulation_bp.route('/')
@login_required
def index():
    campaigns = Campaign.query.filter_by(user_id=current_user.id)\
                              .order_by(Campaign.created_at.desc()).all()
    return render_template('simulation/index.html',
                           campaigns=campaigns, templates=TEMPLATES)


@simulation_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        name        = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        template    = request.form.get('template_type', 'generic')
        target_count = int(request.form.get('target_count', 0))

        if not name:
            flash('Campaign name is required.', 'danger')
            return render_template('simulation/create.html', templates=TEMPLATES)

        camp = Campaign(
            user_id=current_user.id,
            name=name,
            description=description,
            template_type=template if template in TEMPLATES else 'generic',
            target_count=target_count,
            status='active'
        )
        db.session.add(camp)
        db.session.commit()
        _log('CAMPAIGN_CREATE', f'Campaign "{name}" created (template={template})')
        flash(f'Campaign "{name}" created successfully!', 'success')
        return redirect(url_for('simulation.detail', campaign_id=camp.id))

    return render_template('simulation/create.html', templates=TEMPLATES)


@simulation_bp.route('/campaign/<int:campaign_id>')
@login_required
def detail(campaign_id):
    camp = Campaign.query.filter_by(id=campaign_id, user_id=current_user.id).first_or_404()
    clicks = camp.clicks.order_by(CampaignClick.clicked_at.desc()).all()

    sim_url = url_for('simulation.sim_landing', token=camp.token, _external=True)
    return render_template('simulation/detail.html',
                           campaign=camp, clicks=clicks, sim_url=sim_url,
                           templates=TEMPLATES)


@simulation_bp.route('/campaign/<int:campaign_id>/delete', methods=['POST'])
@login_required
def delete(campaign_id):
    camp = Campaign.query.filter_by(id=campaign_id, user_id=current_user.id).first_or_404()
    db.session.delete(camp)
    db.session.commit()
    _log('CAMPAIGN_DELETE', f'Campaign #{campaign_id} deleted')
    flash('Campaign deleted.', 'info')
    return redirect(url_for('simulation.index'))


@simulation_bp.route('/campaign/<int:campaign_id>/complete', methods=['POST'])
@login_required
def complete_campaign(campaign_id):
    camp = Campaign.query.filter_by(id=campaign_id, user_id=current_user.id).first_or_404()
    camp.status = 'completed'
    camp.completed_at = datetime.utcnow()
    db.session.commit()
    flash('Campaign marked as completed.', 'success')
    return redirect(url_for('simulation.detail', campaign_id=campaign_id))


# ── Public simulation landing page ────────────────────────────────────────────

@simulation_bp.route('/sim/<token>')
def sim_landing(token):
    """
    The 'phishing' link endpoint.
    Records the click and immediately shows the EDUCATION page.
    No credentials are ever collected or requested.
    """
    camp = Campaign.query.filter_by(token=token, status='active').first()

    if not camp:
        # Token invalid or campaign ended — show generic education page
        return render_template('simulation/education.html', campaign=None)

    # Record click
    click = CampaignClick(
        campaign_id=camp.id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:500]
    )
    camp.click_count += 1
    db.session.add(click)
    db.session.commit()

    _log('SIM_CLICK', f'Campaign "{camp.name}" (#{camp.id}) click recorded')

    # Immediately redirect to education page — we never collect credentials
    return render_template('simulation/education.html', campaign=camp)


@simulation_bp.route('/sim/<token>/report')
def report_phish(token):
    """User clicked 'Report as phishing' — give positive reinforcement."""
    camp = Campaign.query.filter_by(token=token).first()
    if camp:
        camp.report_count += 1
        db.session.commit()
    return render_template('simulation/good_catch.html', campaign=camp)
