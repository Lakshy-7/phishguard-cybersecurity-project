"""
Domain Analyzer — heuristic analysis of a domain without external API calls.
Extracts registration patterns, TLD risk, keyword density, and structural signals.
"""

import re
import math
from urllib.parse import urlparse
from flask import Blueprint, render_template, request, flash
from flask_login import login_required, current_user

from app.models.log import AuditLog

domain_bp = Blueprint('domain', __name__, url_prefix='/domain')

# TLD risk categories
HIGH_RISK_TLDS   = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.click', '.top',
                    '.win', '.loan', '.pw', '.club', '.online', '.site', '.info',
                    '.biz', '.us.com', '.co.cc'}
MEDIUM_RISK_TLDS = {'.net', '.org', '.biz', '.info', '.co', '.io', '.cc', '.tv',
                    '.mobi', '.name', '.pro', '.tel', '.travel', '.jobs', '.aero'}
LOW_RISK_TLDS    = {'.com', '.edu', '.gov', '.mil', '.int', '.co.uk', '.com.au',
                    '.co.jp', '.de', '.fr', '.ca', '.it', '.es', '.nl', '.se',
                    '.no', '.fi', '.dk', '.ch', '.at', '.be', '.pl'}

PHISHING_KEYWORDS = [
    'verify', 'secure', 'login', 'signin', 'account', 'update', 'confirm',
    'suspended', 'restore', 'validate', 'authenticate', 'billing', 'payment',
    'support', 'service', 'access', 'unlock', 'renew', 'urgent', 'alert',
    'security', 'recover', 'password', 'credential', 'bank', 'wallet',
]

TRUSTED_BRANDS = [
    'paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix', 'facebook',
    'instagram', 'twitter', 'linkedin', 'chase', 'wellsfargo', 'bankofamerica',
    'citibank', 'coinbase', 'binance', 'dropbox', 'onedrive', 'fedex', 'dhl',
    'usps', 'ups', 'irs', 'ebay', 'walmart', 'target', 'bestbuy',
]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())


def analyze_domain(domain_input: str) -> dict:
    """
    Perform heuristic domain analysis. Returns a detailed risk report dict.
    """
    # Normalize input
    raw = domain_input.strip().lower()
    if not raw.startswith('http'):
        raw = 'http://' + raw
    try:
        parsed   = urlparse(raw)
        hostname = parsed.hostname or ''
        path     = parsed.path or ''
    except Exception:
        hostname = raw
        path     = ''

    # Strip www
    domain = hostname.lstrip('www.')
    parts  = domain.split('.')
    tld    = '.' + parts[-1] if parts else ''
    sld    = parts[-2] if len(parts) >= 2 else domain   # second-level domain

    # ── Scoring ────────────────────────────────────────────────────
    risk_score  = 0
    flags       = []
    good_signs  = []

    # TLD risk
    if tld in HIGH_RISK_TLDS:
        risk_score += 30
        flags.append(f"High-risk TLD ({tld}) — frequently abused in phishing")
    elif tld in MEDIUM_RISK_TLDS:
        risk_score += 10
        flags.append(f"Medium-risk TLD ({tld})")
    else:
        good_signs.append(f"Standard TLD ({tld})")

    # Subdomain depth
    subdomain_count = max(0, len(parts) - 2)
    if subdomain_count >= 3:
        risk_score += 20
        flags.append(f"Deep subdomain nesting ({subdomain_count} levels) — common in phishing")
    elif subdomain_count == 2:
        risk_score += 8
        flags.append(f"Multiple subdomains ({subdomain_count} levels)")
    elif subdomain_count == 0:
        good_signs.append("No subdomains — clean domain structure")

    # Domain length
    if len(sld) > 20:
        risk_score += 10
        flags.append(f"Long domain name ({len(sld)} chars)")
    elif len(sld) <= 12:
        good_signs.append("Short, memorable domain name")

    # Hyphens in SLD
    hyphen_count = sld.count('-')
    if hyphen_count >= 3:
        risk_score += 20
        flags.append(f"Excessive hyphens ({hyphen_count}) — sign of domain spoofing")
    elif hyphen_count >= 1:
        risk_score += 8
        flags.append(f"Hyphens present ({hyphen_count})")

    # Shannon entropy of SLD
    entropy = _shannon_entropy(sld)
    if entropy > 3.8:
        risk_score += 15
        flags.append(f"High character entropy ({entropy:.2f}) — domain appears randomly generated")
    elif entropy < 2.5 and len(sld) > 4:
        good_signs.append("Low entropy — domain looks human-readable")

    # Phishing keywords in domain
    kw_hits = [kw for kw in PHISHING_KEYWORDS if kw in domain]
    if len(kw_hits) >= 2:
        risk_score += 20
        flags.append(f"Multiple phishing keywords: {', '.join(kw_hits[:4])}")
    elif len(kw_hits) == 1:
        risk_score += 10
        flags.append(f"Phishing keyword in domain: '{kw_hits[0]}'")

    # Brand name impersonation
    brand_hits = [b for b in TRUSTED_BRANDS if b in domain]
    if brand_hits:
        # Check if this IS actually that brand's real domain
        is_real = any(domain == f'{b}.com' or domain == f'{b}.net' or
                      domain.endswith(f'.{b}.com') for b in brand_hits)
        if not is_real:
            risk_score += 25
            flags.append(f"Brand name impersonation detected: '{brand_hits[0]}' in domain but not official")
        else:
            good_signs.append(f"Verified brand domain: {brand_hits[0]}")

    # IP address used as domain
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        risk_score += 35
        flags.append("IP address used as host — no legitimate business uses raw IPs")

    # Digits in SLD
    digit_count = sum(1 for c in sld if c.isdigit())
    if digit_count >= 4:
        risk_score += 8
        flags.append(f"Many digits in domain ({digit_count}) — common in auto-generated phishing domains")

    # Hex-encoded chars in URL
    hex_count = len(re.findall(r'%[0-9a-f]{2}', raw))
    if hex_count >= 3:
        risk_score += 15
        flags.append(f"URL encoding/obfuscation detected ({hex_count} encoded chars)")

    # @ in URL
    if '@' in hostname:
        risk_score += 25
        flags.append("@ symbol in URL — may redirect to a completely different host")

    # Path phishing keywords
    path_kw = [kw for kw in ['login', 'signin', 'verify', 'secure', 'account', 'password']
               if kw in path.lower()]
    if path_kw:
        risk_score += 5
        flags.append(f"Phishing keywords in path: {', '.join(path_kw[:3])}")

    # No flags = probably clean
    if not flags:
        good_signs.append("No suspicious patterns detected")

    risk_score = min(100, risk_score)

    # Risk level label
    if risk_score >= 70:
        risk_level = 'critical'
    elif risk_score >= 45:
        risk_level = 'high'
    elif risk_score >= 20:
        risk_level = 'medium'
    else:
        risk_level = 'low'

    return {
        'input':          domain_input,
        'hostname':       hostname,
        'domain':         domain,
        'sld':            sld,
        'tld':            tld,
        'subdomain_count': subdomain_count,
        'hyphen_count':   hyphen_count,
        'entropy':        round(entropy, 3),
        'domain_length':  len(sld),
        'keyword_hits':   kw_hits,
        'brand_hits':     brand_hits,
        'risk_score':     risk_score,
        'risk_level':     risk_level,
        'flags':          flags,
        'good_signs':     good_signs,
        'tld_category':   ('high_risk' if tld in HIGH_RISK_TLDS
                           else 'medium_risk' if tld in MEDIUM_RISK_TLDS
                           else 'low_risk'),
    }


@domain_bp.route('/', methods=['GET', 'POST'])
@login_required
def analyze():
    result = None
    domain_input = ''

    if request.method == 'POST':
        domain_input = request.form.get('domain', '').strip()
        if not domain_input:
            flash('Please enter a domain or URL to analyze.', 'warning')
        else:
            result = analyze_domain(domain_input)
            AuditLog.log(
                current_user.id, 'domain_analysis',
                f"Analyzed: {domain_input} → risk={result['risk_score']} ({result['risk_level']})"
            )

    return render_template('domain_analyzer/index.html',
                           result=result, domain_input=domain_input)
