"""
URL Feature Extractor for Phishing Detection.

Extracts numerical features from a URL string that are fed into the ML classifier.
No external HTTP requests are made — all analysis is done on the URL string itself.
"""

import re
import math
from urllib.parse import urlparse


# Known suspicious keywords frequently found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'banking', 'confirm', 'password', 'credential', 'wallet',
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix',
    'support', 'alert', 'suspended', 'unusual', 'activity',
    'free', 'winner', 'prize', 'click', 'urgent', 'limited'
]

# Common legitimate TLDs
LEGITIMATE_TLDS = {'.com', '.org', '.net', '.gov', '.edu', '.co.uk', '.io'}


def extract_url_features(url: str) -> dict:
    """
    Extract a dictionary of ML-ready features from a URL.

    Args:
        url: The URL string to analyze.

    Returns:
        dict of feature_name -> numeric value
    """
    features = {}

    # ── Ensure URL has a scheme for parsing ───────────────────────
    if not url.startswith(('http://', 'https://')):
        parsed_url = urlparse('http://' + url)
    else:
        parsed_url = urlparse(url)

    full_url    = url
    scheme      = parsed_url.scheme.lower()
    netloc      = parsed_url.netloc.lower()
    path        = parsed_url.path
    query       = parsed_url.query
    hostname    = parsed_url.hostname or ''

    # ── Length-based features ──────────────────────────────────────
    features['url_length']      = len(full_url)
    features['hostname_length'] = len(hostname)
    features['path_length']     = len(path)
    features['query_length']    = len(query)

    # ── Character count features ───────────────────────────────────
    features['num_dots']        = full_url.count('.')
    features['num_hyphens']     = full_url.count('-')
    features['num_underscores'] = full_url.count('_')
    features['num_slashes']     = full_url.count('/')
    features['num_question']    = full_url.count('?')
    features['num_equals']      = full_url.count('=')
    features['num_ampersand']   = full_url.count('&')
    features['num_at']          = full_url.count('@')
    features['num_percent']     = full_url.count('%')
    features['num_digits']      = sum(c.isdigit() for c in full_url)

    # ── Entropy of URL (high entropy = random / obfuscated) ───────
    features['url_entropy'] = _shannon_entropy(full_url)

    # ── Subdomain count ────────────────────────────────────────────
    parts = hostname.split('.')
    features['subdomain_count'] = max(0, len(parts) - 2)

    # ── Boolean security features (0 or 1) ────────────────────────
    features['has_https']     = 1 if scheme == 'https' else 0
    features['has_ip_address']= 1 if _is_ip_address(hostname) else 0
    features['has_at_symbol'] = 1 if '@' in netloc else 0
    features['has_double_slash'] = 1 if '//' in path else 0
    features['has_port']      = 1 if parsed_url.port else 0
    features['has_query']     = 1 if query else 0

    # ── Suspicious keyword presence ───────────────────────────────
    url_lower = full_url.lower()
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    features['suspicious_keyword_count'] = keyword_hits
    features['has_suspicious_keyword']   = 1 if keyword_hits > 0 else 0

    # ── TLD features ───────────────────────────────────────────────
    features['has_legitimate_tld'] = 1 if any(hostname.endswith(t) for t in LEGITIMATE_TLDS) else 0
    features['tld_length'] = len(parts[-1]) if parts else 0

    # ── Path depth ────────────────────────────────────────────────
    path_parts = [p for p in path.split('/') if p]
    features['path_depth'] = len(path_parts)

    # ── Hex encoding in URL (obfuscation signal) ──────────────────
    features['hex_encoding_count'] = len(re.findall(r'%[0-9a-fA-F]{2}', full_url))

    # ── Domain age approximation: long random-looking domains ─────
    features['domain_looks_random'] = 1 if _looks_random(hostname) else 0

    return features


def features_to_vector(features: dict) -> list:
    """Convert feature dict to ordered list for the ML model."""
    return [
        features['url_length'],
        features['hostname_length'],
        features['path_length'],
        features['query_length'],
        features['num_dots'],
        features['num_hyphens'],
        features['num_underscores'],
        features['num_slashes'],
        features['num_question'],
        features['num_equals'],
        features['num_ampersand'],
        features['num_at'],
        features['num_percent'],
        features['num_digits'],
        features['url_entropy'],
        features['subdomain_count'],
        features['has_https'],
        features['has_ip_address'],
        features['has_at_symbol'],
        features['has_double_slash'],
        features['has_port'],
        features['has_query'],
        features['suspicious_keyword_count'],
        features['has_suspicious_keyword'],
        features['has_legitimate_tld'],
        features['tld_length'],
        features['path_depth'],
        features['hex_encoding_count'],
        features['domain_looks_random'],
    ]


FEATURE_NAMES = [
    'url_length', 'hostname_length', 'path_length', 'query_length',
    'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
    'num_question', 'num_equals', 'num_ampersand', 'num_at',
    'num_percent', 'num_digits', 'url_entropy', 'subdomain_count',
    'has_https', 'has_ip_address', 'has_at_symbol', 'has_double_slash',
    'has_port', 'has_query', 'suspicious_keyword_count',
    'has_suspicious_keyword', 'has_legitimate_tld', 'tld_length',
    'path_depth', 'hex_encoding_count', 'domain_looks_random'
]


# ── Helper functions ───────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_ip_address(hostname: str) -> bool:
    """Return True if hostname is an IP address (IPv4 or IPv6)."""
    # IPv4
    ipv4_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    # IPv6
    ipv6_pattern = re.compile(r'^\[?[0-9a-fA-F:]+\]?$')
    return bool(ipv4_pattern.match(hostname) or ipv6_pattern.match(hostname))


def _looks_random(hostname: str) -> bool:
    """Heuristic: does the domain look randomly generated?"""
    if not hostname:
        return False
    # Strip TLD
    parts = hostname.split('.')
    domain = parts[-2] if len(parts) >= 2 else hostname
    if len(domain) < 6:
        return False
    # High consonant ratio suggests random string
    vowels = sum(1 for c in domain if c in 'aeiou')
    ratio = vowels / max(len(domain), 1)
    return ratio < 0.2
