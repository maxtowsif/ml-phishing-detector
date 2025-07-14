# features.py
# ---------------------------------------------------------
# 📊 Feature Extraction Module
# Extracts lexical/structural features from URLs
# ---------------------------------------------------------

import numpy as np
from urllib.parse import urlparse
import tldextract
import re
from datetime import datetime
import socket
import ssl
import pandas as pd


def extract_features(url: str) -> dict:
    """
    Extract comprehensive features from a given URL.
    This is the main function called by the application.
    """
    # Basic lexical features
    basic_features = extract_basic_features(url)
    
    # Security features
    security_features = extract_security_features(url)
    
    # Domain features
    domain_features = extract_domain_features(url)
    
    # Combine all features
    all_features = {**basic_features, **security_features, **domain_features}
    
    # Add feature importance for visualization
    feature_importance = calculate_feature_importance(all_features)
    
    return {
        **all_features,
        'feature_importance': feature_importance
    }


def extract_basic_features(url: str) -> dict:
    """
    Extract common lexical and structural features from a given URL.
    These features are used by the ML model to classify the URL.
    """
    parsed          = urlparse(url)
    hostname        = parsed.hostname or ""
    ext             = tldextract.extract(url)

    length_url      = len(url)
    length_hostname = len(hostname)
    nb_dots         = url.count(".")
    nb_hyphens      = url.count("-")
    nb_at           = url.count("@")
    nb_qm           = url.count("?")
    nb_and          = url.count("&")
    nb_or           = url.count("|")
    nb_slash        = url.count("/")
    nb_www          = 1 if "www" in ext.subdomain.split(".") else 0

    digits          = sum(c.isdigit() for c in url)
    ratio_digits    = digits / length_url if length_url else 0.0

    google_index    = 0  # Placeholder
    page_rank       = 0  # Placeholder

    return {
        "length_url": length_url,
        "length_hostname": length_hostname,
        "nb_dots": nb_dots,
        "nb_hyphens": nb_hyphens,
        "nb_at": nb_at,
        "nb_qm": nb_qm,
        "nb_and": nb_and,
        "nb_or": nb_or,
        "nb_slash": nb_slash,
        "nb_www": nb_www,
        "ratio_digits_url": ratio_digits,
        "google_index": google_index,
        "page_rank": page_rank,
    }


def extract_security_features(url: str) -> dict:
    """
    Extract security-related features from URL.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc
    
    # HTTPS check
    https = parsed.scheme == 'https'
    
    # SSL certificate check
    ssl_valid = check_ssl_certificate(domain)
    
    # Suspicious keywords
    suspicious_keywords = count_suspicious_keywords(url)
    
    # Domain age (placeholder - would need WHOIS lookup)
    domain_age_days = 0  # Placeholder
    
    # IP address check
    is_ip_address = check_if_ip_address(domain)
    
    # Subdomain count
    subdomain_count = len(domain.split('.')) - 1
    
    # Path length
    path_length = len(parsed.path)
    
    # Query parameters count
    query_count = len(parsed.query.split('&')) if parsed.query else 0
    
    return {
        "https": https,
        "ssl_valid": ssl_valid,
        "suspicious_keywords": suspicious_keywords,
        "domain_age_days": domain_age_days,
        "is_ip_address": is_ip_address,
        "subdomain_count": subdomain_count,
        "path_length": path_length,
        "query_count": query_count
    }


def extract_domain_features(url: str) -> dict:
    """
    Extract domain-specific features.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc
    
    # Domain length
    domain_length = len(domain)
    
    # TLD length
    tld = domain.split('.')[-1] if '.' in domain else ''
    tld_length = len(tld)
    
    # Character frequency
    vowels = sum(1 for c in domain.lower() if c in 'aeiou')
    consonants = sum(1 for c in domain.lower() if c.isalpha() and c not in 'aeiou')
    
    # Special characters
    special_chars = sum(1 for c in domain if not c.isalnum() and c != '.')
    
    # Entropy (measure of randomness)
    entropy = calculate_entropy(domain)
    
    return {
        "domain_length": domain_length,
        "tld_length": tld_length,
        "vowel_count": vowels,
        "consonant_count": consonants,
        "special_char_count": special_chars,
        "entropy": entropy
    }


def check_ssl_certificate(domain: str) -> bool:
    """
    Check if domain has valid SSL certificate.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return True
    except:
        return False


def count_suspicious_keywords(url: str) -> int:
    """
    Count suspicious keywords in URL.
    """
    suspicious_words = [
        'login', 'signin', 'account', 'verify', 'secure', 'update',
        'bank', 'paypal', 'credit', 'card', 'password', 'confirm',
        'security', 'alert', 'warning', 'suspended', 'locked'
    ]
    
    url_lower = url.lower()
    count = 0
    for word in suspicious_words:
        if word in url_lower:
            count += 1
    
    return count


def check_if_ip_address(domain: str) -> bool:
    """
    Check if domain is an IP address.
    """
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    """
    if not text:
        return 0.0
    
    # Count character frequencies
    char_count = {}
    for char in text:
        char_count[char] = char_count.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    length = len(text)
    for count in char_count.values():
        probability = count / length
        entropy -= probability * np.log2(probability)
    
    return entropy


def calculate_feature_importance(features: dict) -> dict:
    """
    Calculate feature importance for visualization.
    """
    # Define importance weights for different feature categories
    importance_weights = {
        # High importance features
        'suspicious_keywords': 0.9,
        'ssl_valid': 0.8,
        'https': 0.7,
        'is_ip_address': 0.7,
        'domain_age_days': 0.6,
        
        # Medium importance features
        'length_url': 0.5,
        'nb_dots': 0.5,
        'nb_hyphens': 0.4,
        'subdomain_count': 0.4,
        'entropy': 0.4,
        
        # Lower importance features
        'nb_at': 0.3,
        'nb_qm': 0.3,
        'nb_and': 0.3,
        'nb_or': 0.3,
        'nb_slash': 0.2,
        'ratio_digits_url': 0.2,
        'vowel_count': 0.1,
        'consonant_count': 0.1,
        'special_char_count': 0.1
    }
    
    # Calculate weighted importance
    feature_importance = {}
    for feature, value in features.items():
        if feature in importance_weights:
            # Normalize the value and apply weight
            if isinstance(value, (int, float)):
                normalized_value = min(1.0, abs(value) / 100)  # Normalize to 0-1
                feature_importance[feature] = normalized_value * importance_weights[feature]
            else:
                feature_importance[feature] = importance_weights[feature]
    
    return feature_importance


def build_feature_vector(url: str, feat_list: list) -> pd.DataFrame:
    """
    Build a feature vector aligned with the feature list expected by the model.
    Missing features are padded with 0 to maintain dimensionality.
    Returns a DataFrame with correct columns for scaler/model.
    """
    base = extract_basic_features(url)
    vector = [base.get(f, 0) for f in feat_list]
    return pd.DataFrame([vector], columns=feat_list)
