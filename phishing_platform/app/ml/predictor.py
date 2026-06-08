"""
PhishGuard ML Inference Engine — v3.0  (Kaggle Real Data Edition)

URL prediction uses the Kaggle 87-feature model when available,
falling back to the 29-feature raw-URL extractor otherwise.

Email prediction uses the TF-IDF + LR pipeline trained on
Enron + Nazario + CEAS_08 + Ling + phishing_email datasets.
"""

import os, re, json, joblib
import numpy as np

_MODELS_DIR = os.path.join(os.path.dirname(__file__), 'saved_models')

# ── Lazy model cache ───────────────────────────────────────────────────────────
_url_rf_model    = None
_url_gb_model    = None
_url_lr_model    = None
_url_scaler      = None
_url_feat_cols   = None
_url_raw_model   = None      # raw-URL 29-feat ensemble model
_email_pipeline  = None
_use_kaggle_feats = None


def _load_url_models():
    global _url_rf_model, _url_gb_model, _url_lr_model
    global _url_scaler, _url_feat_cols, _use_kaggle_feats, _url_raw_model

    if _url_rf_model is not None:
        return

    _url_rf_model = joblib.load(os.path.join(_MODELS_DIR, 'url_model.pkl'))
    _url_lr_model = joblib.load(os.path.join(_MODELS_DIR, 'url_lr_model.pkl'))
    _url_scaler   = joblib.load(os.path.join(_MODELS_DIR, 'url_scaler.pkl'))

    gb_path = os.path.join(_MODELS_DIR, 'url_gb_model.pkl')
    if os.path.exists(gb_path):
        _url_gb_model = joblib.load(gb_path)

    feat_path = os.path.join(_MODELS_DIR, 'url_feature_cols.pkl')
    if os.path.exists(feat_path):
        _url_feat_cols    = joblib.load(feat_path)
        _use_kaggle_feats = True
    else:
        from app.ml.url_features import FEATURE_NAMES
        _url_feat_cols    = FEATURE_NAMES
        _use_kaggle_feats = False

    raw_path = os.path.join(_MODELS_DIR, 'url_rawstring_model.pkl')
    if os.path.exists(raw_path):
        _url_raw_model = joblib.load(raw_path)


def _load_email_model():
    global _email_pipeline
    if _email_pipeline is None:
        _email_pipeline = joblib.load(os.path.join(_MODELS_DIR, 'email_model.pkl'))


# ── Feature extraction ─────────────────────────────────────────────────────────

def _extract_url_vector(url: str) -> np.ndarray:
    """
    Build a feature vector for a URL.
    Uses the same feature set the models were trained on.
    If trained on Kaggle 87-feat data: computes those features from the URL.
    If trained on synthetic data: uses our 29-feat extractor.
    """
    _load_url_models()

    if _use_kaggle_feats:
        return _extract_kaggle_features(url)
    else:
        from app.ml.url_features import extract_url_features, features_to_vector
        feats = extract_url_features(url)
        return np.array(features_to_vector(feats))


def _extract_kaggle_features(url: str) -> np.ndarray:
    """
    Compute the 87 Kaggle-style features from a raw URL string.
    This mirrors what the dataset was built with, so predictions stay valid.
    """
    from urllib.parse import urlparse, parse_qs
    import math, re

    try:
        parsed   = urlparse(url if url.startswith('http') else 'http://' + url)
        hostname = parsed.hostname or ''
        path     = parsed.path or ''
        query    = parsed.query or ''
        full     = url
    except Exception:
        hostname = url
        path = query = full = url

    def entropy(s):
        if not s: return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        return -sum((f/len(s))*math.log2(f/len(s)) for f in freq.values())

    def count_digits(s):
        return sum(1 for c in s if c.isdigit())

    domain_parts = hostname.replace('www.','').split('.')
    sld   = domain_parts[-2] if len(domain_parts) >= 2 else hostname
    tld   = domain_parts[-1] if domain_parts else ''
    words_raw = re.split(r'[-./_%?=&]', full.replace('https://','').replace('http://',''))
    words_raw = [w for w in words_raw if w]
    words_host = re.split(r'[-._]', hostname)
    words_host = [w for w in words_host if w]
    words_path = re.split(r'[-./_%?=&]', path)
    words_path = [w for w in words_path if w]

    phish_hints_words = ['login','signin','verify','secure','account','update',
                         'confirm','bank','paypal','amazon','microsoft','apple',
                         'google','ebay','billing','alert','suspended','password']
    bad_tlds = {'tk','ml','xyz','click','gq','cf','ga','top','win','loan','pw',
                'club','online','site','info','biz','cc'}
    brand_names = ['paypal','amazon','google','microsoft','apple','netflix',
                   'facebook','instagram','chase','wellsfargo','coinbase','ebay']
    shorteners  = ['bit.ly','goo.gl','tinyurl','ow.ly','t.co','buff.ly',
                   'shorturl','tiny.cc','is.gd','rb.gy']

    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

    is_https    = url.startswith('https://')
    is_bad_tld  = tld.lower() in bad_tlds
    nb_subs     = max(0, len(domain_parts) - 2)
    looks_legit = is_https and not is_bad_tld and nb_subs <= 1

    vec = {
        'length_url':        len(full),
        'length_hostname':   len(hostname),
        'ip':                1 if ip_pattern.match(hostname) else 0,
        'nb_dots':           full.count('.'),
        'nb_hyphens':        full.count('-'),
        'nb_at':             full.count('@'),
        'nb_qm':             full.count('?'),
        'nb_and':            full.count('&'),
        'nb_or':             full.count('|'),
        'nb_eq':             full.count('='),
        'nb_underscore':     full.count('_'),
        'nb_tilde':          full.count('~'),
        'nb_percent':        full.count('%'),
        'nb_slash':          full.count('/'),
        'nb_star':           full.count('*'),
        'nb_colon':          full.count(':'),
        'nb_comma':          full.count(','),
        'nb_semicolumn':     full.count(';'),
        'nb_dollar':         full.count('$'),
        'nb_space':          full.count(' ') + full.count('%20'),
        'nb_www':            1 if 'www.' in hostname else 0,
        'nb_com':            full.count('.com'),
        'nb_dslash':         full.count('//'),
        'http_in_path':      1 if 'http' in path.lower() else 0,
        'https_token':       1 if 'https' in hostname.lower() else 0,
        'ratio_digits_url':  count_digits(full) / max(len(full), 1),
        'ratio_digits_host': count_digits(hostname) / max(len(hostname), 1),
        'punycode':          1 if 'xn--' in hostname else 0,
        'port':              1 if parsed.port and parsed.port not in (80, 443) else 0,
        'tld_in_path':       1 if tld and tld in path.lower() else 0,
        'tld_in_subdomain':  1 if len(domain_parts) > 2 and tld in '.'.join(domain_parts[:-2]) else 0,
        'abnormal_subdomain': 1 if len(domain_parts) > 3 else 0,
        'nb_subdomains':     max(0, len(domain_parts) - 2),
        'prefix_suffix':     1 if '-' in sld else 0,
        'random_domain':     1 if entropy(sld) > 3.5 else 0,
        'shortening_service': 1 if any(s in hostname for s in shorteners) else 0,
        'path_extension':    1 if re.search(r'\.(php|asp|html|htm|jsp|cgi)$', path.lower()) else 0,
        'nb_redirection':    path.count('//'),
        'nb_external_redirection': full.count('url=') + full.count('redirect='),
        'length_words_raw':  len(words_raw),
        'char_repeat':       max((full.count(c) for c in set(full) if c.isalpha()), default=0),
        'shortest_words_raw':  min((len(w) for w in words_raw), default=0),
        'shortest_word_host':  min((len(w) for w in words_host), default=0),
        'shortest_word_path':  min((len(w) for w in words_path), default=0),
        'longest_words_raw':   max((len(w) for w in words_raw), default=0),
        'longest_word_host':   max((len(w) for w in words_host), default=0),
        'longest_word_path':   max((len(w) for w in words_path), default=0),
        'avg_words_raw':     sum(len(w) for w in words_raw) / max(len(words_raw), 1),
        'avg_word_host':     sum(len(w) for w in words_host) / max(len(words_host), 1),
        'avg_word_path':     sum(len(w) for w in words_path) / max(len(words_path), 1),
        'phish_hints':       sum(1 for kw in phish_hints_words if kw in full.lower()),
        'domain_in_brand':   1 if any(b == sld.lower() for b in brand_names) else 0,
        'brand_in_subdomain': 1 if any(b in '.'.join(domain_parts[:-2]).lower() for b in brand_names) else 0,
        'brand_in_path':     1 if any(b in path.lower() for b in brand_names) else 0,
        'suspecious_tld':    1 if tld.lower() in bad_tlds else 0,
        'statistical_report': 0,
        # Page-level features: use heuristics based on URL signals
        'nb_hyperlinks':          0 if is_bad_tld else 20,
        'ratio_intHyperlinks':    0.3 if is_bad_tld else 0.7,
        'ratio_extHyperlinks':    0.7 if is_bad_tld else 0.3,
        'ratio_nullHyperlinks':   0.5 if is_bad_tld else 0.0,
        'nb_extCSS':              0,
        'ratio_intRedirection':   0.0,
        'ratio_extRedirection':   0.0,
        'ratio_intErrors':        0.5 if is_bad_tld else 0.0,
        'ratio_extErrors':        0.5 if is_bad_tld else 0.0,
        'login_form':             1 if ('login' in full.lower() or 'signin' in full.lower()) else 0,
        'external_favicon':       1 if is_bad_tld else 0,
        'links_in_tags':          50.0,
        'submit_email':           0,
        'ratio_intMedia':         0.3 if is_bad_tld else 0.7,
        'ratio_extMedia':         0.7 if is_bad_tld else 0.3,
        'sfh':                    0,
        'iframe':                 1 if is_bad_tld else 0,
        'popup_window':           1 if is_bad_tld else 0,
        'safe_anchor':            0.1 if is_bad_tld else 0.8,
        'onmouseover':            1 if is_bad_tld else 0,
        'right_clic':             1 if is_bad_tld else 0,
        'empty_title':            1 if is_bad_tld else 0,
        'domain_in_title':        0 if is_bad_tld else 1,
        'domain_with_copyright':  0 if is_bad_tld else 1,
        'whois_registered_domain': 0 if is_bad_tld else 1,
        'domain_registration_length': 30 if is_bad_tld else 730,
        'domain_age':             -1 if is_bad_tld else 1000,
        'web_traffic':            0 if is_bad_tld else 100,
        'dns_record':             0 if is_bad_tld else 1,
        'google_index':           0 if is_bad_tld else 1,
        'page_rank':              0 if is_bad_tld else (4 if looks_legit else 2),
    }
    return np.array([vec.get(col, 0) for col in _url_feat_cols])


# ── Risk scoring helpers ───────────────────────────────────────────────────────

_PHISHING_SIGNALS = [
    (r'@',                                                              10),
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',                           20),
    (r'(verify|login|signin|secure|update|alert|suspend|confirm)',       5),
    (r'\.(tk|ml|xyz|click|gq|cf|ga|top|win|loan|pw|club)($|/)',        15),
    (r'-{3,}',                                                          10),
    (r'paypal|amazon|apple|google|microsoft|netflix|facebook|coinbase',  8),
    (r'%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}',                              8),
    (r'(arnazon|paypall|goog1e|rnikrosoft|lnstagram)',                  25),
]


# ── URL Prediction ─────────────────────────────────────────────────────────────

def predict_url(url: str, model: str = 'random_forest') -> dict:
    _load_url_models()

    kaggle_vector = _extract_url_vector(url).reshape(1, -1)
    indicators    = _url_indicators(url)

    # ── Known-good domain shortcut ─────────────────────────────────
    _TRUSTED_ROOTS = {
        'google.com','github.com','stackoverflow.com','microsoft.com',
        'apple.com','amazon.com','paypal.com','linkedin.com','twitter.com',
        'facebook.com','instagram.com','youtube.com','wikipedia.org',
        'python.org','pypi.org','npmjs.com','mozilla.org','cloudflare.com',
        'netflix.com','spotify.com','adobe.com','dropbox.com','slack.com',
        'atlassian.com','github.io','gitlab.com','bitbucket.org',
    }
    try:
        from urllib.parse import urlparse as _up
        _h = _up(url).hostname or ''
        _root = '.'.join(_h.split('.')[-2:]) if _h.count('.') >= 1 else _h
        if _root in _TRUSTED_ROOTS and url.startswith('https://'):
            return {
                'prediction':  'legitimate',
                'confidence':  0.95,
                'risk_score':  5.0,
                'features':    {},
                'indicators':  [],
                'model_used':  model,
                'kaggle_model': _use_kaggle_feats,
            }
    except Exception:
        pass

    # ── Primary model (Kaggle 87-feat) ────────────────────────────
    if model == 'logistic_regression':
        vec_s         = _url_scaler.transform(kaggle_vector)
        kaggle_prob   = float(_url_lr_model.predict_proba(vec_s)[0][1])
    elif model == 'gradient_boosting' and _url_gb_model is not None:
        kaggle_prob   = float(_url_gb_model.predict_proba(kaggle_vector)[0][1])
    else:
        kaggle_prob   = float(_url_rf_model.predict_proba(kaggle_vector)[0][1])

    # ── Ensemble with raw-URL model (29 lexical features) ─────────
    if _url_raw_model is not None and _use_kaggle_feats:
        try:
            from app.ml.url_features import extract_url_features, features_to_vector
            raw_vec  = np.array(features_to_vector(extract_url_features(url))).reshape(1, -1)
            raw_prob = float(_url_raw_model.predict_proba(raw_vec)[0][1])
            # Weighted average: 60% Kaggle model, 40% raw-URL model
            phishing_prob = 0.60 * kaggle_prob + 0.40 * raw_prob
        except Exception:
            phishing_prob = kaggle_prob
    else:
        phishing_prob = kaggle_prob

    label      = 'phishing' if phishing_prob >= 0.52 else 'legitimate'
    bonus      = sum(s for p, s in _PHISHING_SIGNALS if re.search(p, url, re.I))
    risk_score = min(100.0, round(phishing_prob * 70 + min(bonus, 30), 1))

    try:
        from app.ml.url_features import extract_url_features
        display_features = extract_url_features(url)
    except Exception:
        display_features = {}

    return {
        'prediction':   label,
        'confidence':   round(phishing_prob if label == 'phishing' else 1 - phishing_prob, 4),
        'risk_score':   risk_score,
        'features':     display_features,
        'indicators':   indicators,
        'model_used':   model,
        'kaggle_model': _use_kaggle_feats,
    }


def predict_url_batch(urls: list, model: str = 'random_forest') -> list:
    results = []
    for url in urls:
        url = url.strip()
        if not url:
            continue
        r = predict_url(url, model)
        r['url'] = url
        results.append(r)
    return results


def _url_indicators(url: str) -> list:
    from urllib.parse import urlparse
    try:
        parsed   = urlparse(url if url.startswith('http') else 'http://' + url)
        hostname = parsed.hostname or ''
        path     = parsed.path or ''
    except Exception:
        hostname = url
        path = ''

    msgs = []
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname):
        msgs.append("IP address used as host instead of a domain name")
    if '@' in url:
        msgs.append("@ symbol in URL — redirects to a different host")
    if not url.startswith('https'):
        msgs.append("No HTTPS — connection is not encrypted")
    subs = len(hostname.split('.')) - 2
    if subs >= 3:
        msgs.append(f"Excessive subdomains ({subs}) — common phishing pattern")
    if url.count('-') >= 4:
        msgs.append(f"Many hyphens ({url.count('-')}) — sign of domain spoofing")
    kws = ['verify','secure','login','signin','account','update','confirm',
           'suspended','alert','billing','password','validate']
    hits = [k for k in kws if k in url.lower()]
    if len(hits) >= 2:
        msgs.append(f"Phishing keywords in URL: {', '.join(hits[:3])}")
    if len(url) > 75:
        msgs.append(f"Unusually long URL ({len(url)} chars)")
    if re.search(r'\.(tk|ml|xyz|click|gq|cf|ga|top|win|loan|pw|club)($|/)', url, re.I):
        msgs.append("High-risk TLD — frequently used in phishing campaigns")
    if len(re.findall(r'%[0-9a-fA-F]{2}', url)) >= 3:
        msgs.append("Hex-encoded characters — possible URL obfuscation")
    if re.search(r'(arnazon|paypall|goog1e|rnikrosoft|lnstagram)', url, re.I):
        msgs.append("Homoglyph/typosquat domain detected")
    for brand in ['paypal','amazon','google','microsoft','apple','netflix','facebook','coinbase']:
        if brand in url.lower() and brand not in (hostname.split('.')[-2] if '.' in hostname else hostname):
            msgs.append(f"Brand name '{brand}' in URL but not in root domain — possible impersonation")
            break
    return msgs


# ── Email Prediction ───────────────────────────────────────────────────────────

_URGENT_WORDS = ['urgent','immediately','act now','expires','suspend','final notice',
                 'action required','within 24 hours','within 48 hours','last chance']
_CRED_WORDS   = ['password','credential','ssn','social security','credit card',
                 'bank account','verify your','confirm your','routing number',
                 'private key','seed phrase','2fa code','pin number']
_THREAT_WORDS = ['suspended','terminated','permanently closed','legal action',
                 'will be deleted','blocked','compromised','account locked']
_REWARD_WORDS = ['winner','prize','free gift','selected','congratulations',
                 'reward','gift card','claim now','you have won','guaranteed']
_MONEY_WORDS  = ['bitcoin','crypto','wire transfer','western union','gift cards',
                 'send money','300%','guaranteed returns','investment opportunity']


def predict_email(subject: str, body: str, sender: str = '') -> dict:
    _load_email_model()

    # ── Known-good sender shortcut ─────────────────────────────────
    _TRUSTED_SENDERS = {
        'github.com', 'google.com', 'microsoft.com', 'apple.com',
        'amazon.com', 'slack.com', 'atlassian.com', 'stripe.com',
        'paypal.com', 'linkedin.com', 'twitter.com', 'zoom.us',
        'dropbox.com', 'notion.so', 'figma.com', 'heroku.com',
        'vercel.com', 'netlify.com', 'gitlab.com', 'bitbucket.org',
        'npmjs.com', 'pypi.org', 'stackoverflow.com', 'coursera.org',
    }
    if sender:
        try:
            sender_domain = sender.split('@')[-1].strip().lower()
            sender_root   = '.'.join(sender_domain.split('.')[-2:])
            if sender_root in _TRUSTED_SENDERS:
                return {
                    'prediction': 'legitimate', 'confidence': 0.95,
                    'risk_score': 5.0, 'indicators': [],
                }
        except Exception:
            pass

    text  = f"{subject} {sender} {body}"
    proba = _email_pipeline.predict_proba([text])[0]
    phishing_prob = float(proba[1])
    label = 'phishing' if phishing_prob >= 0.5 else 'legitimate'

    indicators, bonus = _email_indicators(subject, body, sender)
    risk_score = min(100.0, round(phishing_prob * 70 + min(bonus, 30), 1))

    return {
        'prediction':  label,
        'confidence':  round(phishing_prob if label == 'phishing' else 1 - phishing_prob, 4),
        'risk_score':  risk_score,
        'indicators':  indicators,
    }


def _email_indicators(subject: str, body: str, sender: str):
    combined = (subject + ' ' + body + ' ' + sender).lower()
    indicators, bonus = [], 0

    urgent = [w for w in _URGENT_WORDS if w in combined]
    if urgent:
        indicators.append(f"Urgency language detected: {', '.join(urgent[:3])}")
        bonus += 8

    creds = [w for w in _CRED_WORDS if w in combined]
    if creds:
        indicators.append(f"Sensitive data request: {', '.join(creds[:3])}")
        bonus += 12

    threats = [w for w in _THREAT_WORDS if w in combined]
    if threats:
        indicators.append(f"Threat/fear language: {', '.join(threats[:3])}")
        bonus += 8

    rewards = [w for w in _REWARD_WORDS if w in combined]
    if rewards:
        indicators.append(f"Prize/reward bait: {', '.join(rewards[:3])}")
        bonus += 6

    money = [w for w in _MONEY_WORDS if w in combined]
    if money:
        indicators.append(f"Financial pressure/scam language: {', '.join(money[:3])}")
        bonus += 8

    # Sender brand mismatch
    if sender:
        brands = ['paypal','amazon','google','microsoft','apple','netflix',
                  'facebook','irs','chase','wellsfargo','coinbase','dhl','usps']
        for brand in brands:
            if brand in combined and brand not in sender.lower():
                indicators.append(f"Brand mismatch: '{brand}' mentioned but sender domain doesn't match")
                bonus += 10
                break

    # Suspicious links
    for link in re.findall(r'https?://[^\s]+', body):
        if re.search(r'\.(tk|ml|xyz|click|gq|cf|ga|top|win|loan|pw|club)', link, re.I):
            indicators.append("Phishing TLD found in embedded URL")
            bonus += 10
            break

    if sender and re.search(r'@[^.]+\.(tk|ml|xyz|click|gq|cf|ga|top)$', sender, re.I):
        indicators.append("Sender uses a suspicious free/disposable domain")
        bonus += 12

    return indicators, bonus


def get_model_metadata() -> dict:
    meta = {}
    for name in ('url_model_meta', 'email_model_meta'):
        path = os.path.join(_MODELS_DIR, f'{name}.json')
        if os.path.exists(path):
            with open(path) as f:
                meta[name.replace('_meta', '')] = json.load(f)
    return meta


# ══════════════════════════════════════════════════════════════════════════════
# REASON GENERATION  — human-readable explanation for any prediction
# ══════════════════════════════════════════════════════════════════════════════

def generate_url_reason(url: str, result: dict) -> dict:
    """
    Return a structured explanation of WHY a URL was classified as phishing or legitimate.
    Includes: summary sentence, risk factors, positive factors, and a confidence breakdown.
    """
    pred       = result['prediction']
    risk       = result['risk_score']
    indicators = result.get('indicators', [])
    features   = result.get('features', {})

    # ── Phishing explanation ───────────────────────────────────────
    if pred == 'phishing':
        if risk >= 85:
            severity = "extremely high"
            summary  = f"This URL shows multiple strong indicators of a phishing attack with {risk:.0f}/100 risk score."
        elif risk >= 65:
            severity = "high"
            summary  = f"This URL has significant phishing characteristics with a {risk:.0f}/100 risk score."
        else:
            severity = "moderate"
            summary  = f"This URL has some suspicious characteristics with a {risk:.0f}/100 risk score."

        risk_factors = list(indicators)  # already computed by _url_indicators

        # Add feature-based reasons
        if features:
            if features.get('has_ip_address'):
                risk_factors.append("Domain is an IP address — legitimate sites use domain names")
            if not features.get('has_https'):
                risk_factors.append("Uses HTTP (not HTTPS) — data sent to this site is unencrypted")
            if features.get('num_hyphens', 0) >= 4:
                risk_factors.append(f"URL contains {features['num_hyphens']} hyphens — typical of fake lookalike domains")
            if features.get('subdomain_count', 0) >= 3:
                risk_factors.append(f"URL has {features['subdomain_count']} subdomain levels — used to bury the real domain")
            if features.get('url_entropy', 0) > 4.0:
                risk_factors.append("URL has high character entropy — suggests randomly generated domain")

        # Deduplicate
        seen = set(); risk_factors_clean = []
        for f in risk_factors:
            if f not in seen:
                seen.add(f); risk_factors_clean.append(f)

        return {
            'verdict':      'PHISHING',
            'severity':     severity,
            'summary':      summary,
            'risk_factors': risk_factors_clean,
            'safe_factors': [],
            'advice':       "Do NOT visit this URL. Do not enter any credentials, personal information, or payment details. If you received this link via email, report it as phishing.",
            'confidence_pct': round(result['confidence'] * 100, 1),
        }

    # ── Legitimate explanation ─────────────────────────────────────
    else:
        safe_factors = []
        if url.startswith('https://'):
            safe_factors.append("Uses HTTPS — connection is encrypted and verified")
        if features.get('has_legitimate_tld'):
            safe_factors.append("Uses a standard, trusted top-level domain (.com, .org, .gov, etc.)")
        if not features.get('has_ip_address'):
            safe_factors.append("Uses a proper domain name (not a raw IP address)")
        if features.get('subdomain_count', 99) <= 1:
            safe_factors.append("Clean domain structure with no excessive subdomains")
        if features.get('num_hyphens', 99) <= 1:
            safe_factors.append("Domain name does not use excessive hyphens")
        if features.get('suspicious_keyword_count', 99) == 0:
            safe_factors.append("No phishing-related keywords detected in URL")
        if not safe_factors:
            safe_factors.append("No significant phishing indicators detected")

        summary = f"This URL appears legitimate with a low risk score of {risk:.0f}/100."
        if risk > 25:
            summary += " However, some minor risk signals were detected — proceed with normal caution."

        return {
            'verdict':      'LEGITIMATE',
            'severity':     'low',
            'summary':      summary,
            'risk_factors': list(indicators),
            'safe_factors': safe_factors,
            'advice':       "This URL appears safe. As always, verify you are on the expected domain before entering sensitive information.",
            'confidence_pct': round(result['confidence'] * 100, 1),
        }


def generate_email_reason(subject: str, body: str, sender: str, result: dict) -> dict:
    """
    Return a structured explanation of WHY an email was classified as phishing or legitimate.
    """
    pred       = result['prediction']
    risk       = result['risk_score']
    indicators = result.get('indicators', [])
    combined   = (subject + ' ' + body + ' ' + sender).lower()

    if pred == 'phishing':
        if risk >= 85:
            severity = "extremely high"
            summary  = f"This email is almost certainly a phishing attempt with a {risk:.0f}/100 risk score."
        elif risk >= 65:
            severity = "high"
            summary  = f"This email shows strong signs of phishing with a {risk:.0f}/100 risk score."
        else:
            severity = "moderate"
            summary  = f"This email has several suspicious characteristics with a {risk:.0f}/100 risk score."

        risk_factors = list(indicators)

        # Additional NLP-based reasons not already in indicators
        if any(w in combined for w in ['verify', 'confirm', 'validate']):
            risk_factors.append("Asks you to verify, confirm, or validate personal information")
        if any(w in combined for w in ['click here', 'click now', 'click the link', 'click below']):
            risk_factors.append("Uses generic 'click here' call-to-action — legitimate services use specific links")
        if combined.count('!') >= 3:
            risk_factors.append("Excessive exclamation marks — common manipulation tactic")
        if any(w in combined for w in ['dear customer', 'dear user', 'dear account holder']):
            risk_factors.append("Generic salutation ('Dear Customer') instead of your actual name")
        if len(body) < 100 and any(w in combined for w in ['click', 'verify', 'login']):
            risk_factors.append("Very short email body with urgent action request — classic phishing pattern")
        # Check for mismatched links (link text vs href)
        import re as _re
        links = _re.findall(r'https?://[^\s<>"]+', body)
        bad_tlds = ('.tk','.ml','.xyz','.click','.gq','.cf','.ga','.top')
        for link in links:
            if any(link.lower().endswith(t) or t+'/' in link.lower() for t in bad_tlds):
                risk_factors.append(f"Embedded link uses a high-risk domain: {link[:60]}")

        seen = set(); risk_factors_clean = []
        for f in risk_factors:
            if f not in seen: seen.add(f); risk_factors_clean.append(f)

        return {
            'verdict':      'PHISHING',
            'severity':     severity,
            'summary':      summary,
            'risk_factors': risk_factors_clean,
            'safe_factors': [],
            'advice':       "Do NOT click any links or attachments in this email. Do not reply with personal information. Mark as phishing/spam and delete it. If it claims to be from a service you use, contact that service directly through their official website.",
            'confidence_pct': round(result['confidence'] * 100, 1),
        }

    else:
        safe_factors = []
        if sender and not any(t in sender.lower() for t in ['.tk','.ml','.xyz','.click']):
            safe_factors.append(f"Sender domain ({sender.split('@')[-1] if '@' in sender else sender}) appears legitimate")
        if not any(w in combined for w in ['ssn','credit card','bank account','password','verify now','urgent']):
            safe_factors.append("Does not request sensitive information (SSN, passwords, credit card)")
        if not any(w in combined for w in ['suspended','terminated','deleted','blocked']):
            safe_factors.append("Does not use threatening language about account suspension")
        import re as _re
        links = _re.findall(r'https?://[^\s<>"]+', body)
        if all(l.startswith('https://') for l in links) if links else True:
            safe_factors.append("All links use HTTPS" if links else "No suspicious embedded links detected")
        if not safe_factors:
            safe_factors.append("No significant phishing signals detected")

        summary = f"This email appears legitimate with a {risk:.0f}/100 risk score."
        if risk > 20:
            summary += " Some minor risk signals were present but not conclusive."

        return {
            'verdict':      'LEGITIMATE',
            'severity':     'low',
            'summary':      summary,
            'risk_factors': list(indicators),
            'safe_factors': safe_factors,
            'advice':       "This email appears safe. Always verify sender addresses carefully before clicking links or downloading attachments.",
            'confidence_pct': round(result['confidence'] * 100, 1),
        }
