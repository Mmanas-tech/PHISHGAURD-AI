from __future__ import annotations

import re
from typing import Optional


def count_login_forms(html: str) -> int:
    """Count login/password forms in HTML."""
    password_fields = len(
        re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', html, re.IGNORECASE)
    )
    login_inputs = len(
        re.findall(
            r'<input[^>]*(?:name|id|placeholder)=["\'][^"\']*(?:login|email|user|pass)[^"\']*["\'][^>]*>',
            html,
            re.IGNORECASE,
        )
    )
    return max(password_fields, login_inputs)


def count_password_fields(html: str) -> int:
    """Count password input fields."""
    return len(
        re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', html, re.IGNORECASE)
    )


def count_credit_card_fields(html: str) -> int:
    """Count credit card related input fields."""
    cc_patterns = [
        r'<input[^>]*(?:name|id|placeholder)=["\'][^"\']*(?:cc|credit|card|cvv|cvc|pan)[^"\']*["\'][^>]*>',
        r'<input[^>]*autocomplete=["\'][^"\']*(?:cc-|credit-card)[^"\']*["\'][^>]*>',
    ]
    count = 0
    for pattern in cc_patterns:
        count += len(re.findall(pattern, html, re.IGNORECASE))
    return count


def detect_brand_mentions(html: str) -> list[str]:
    """Detect brand name mentions in HTML content."""
    brands = [
        "paypal", "apple", "microsoft", "google", "amazon", "netflix",
        "facebook", "instagram", "twitter", "linkedin", "dropbox",
        "bank of america", "wells fargo", "chase", "citibank", "usaa",
    ]
    html_lower = html.lower()
    return [brand for brand in brands if brand in html_lower]


def calculate_urgency_score(html: str) -> float:
    """Calculate urgency language score (0-1)."""
    urgency_patterns = [
        r"act\s+now",
        r"immediate(ly)?",
        r"urgent",
        r"expires?\s+(today|soon|now)",
        r"limited\s+time",
        r"last\s+chance",
        r"don'?t\s+miss",
        r"verify\s+(your|account|identity)",
        r"confirm\s+(your|account|identity)",
        r"account\s+(suspended|locked|compromised)",
        r"unauthorized\s+(access|activity)",
        r"security\s+(alert|warning|breach)",
        r"click\s+(here|immediately|now)",
    ]
    count = 0
    for pattern in urgency_patterns:
        if re.search(pattern, html, re.IGNORECASE):
            count += 1
    return min(1.0, count / 5.0)


def count_hidden_elements(html: str) -> int:
    """Count hidden elements with potentially sensitive content."""
    hidden_patterns = [
        r'<div[^>]*style=["\'][^"\']*display\s*:\s*none[^"\']*["\'][^>]*>.*?</div>',
        r'<div[^>]*style=["\'][^"\']*visibility\s*:\s*hidden[^"\']*["\'][^>]*>.*?</div>',
        r'<input[^>]*type=["\']hidden["\'][^>]*>',
    ]
    count = 0
    for pattern in hidden_patterns:
        count += len(re.findall(pattern, html, re.IGNORECASE | re.DOTALL))
    return count


def count_external_resources(html: str, page_domain: str = "") -> int:
    """Count external resource domains referenced in HTML."""
    src_patterns = [
        r'(?:src|href|action)=["\']?(https?://[^"\s\'<>]+)',
    ]
    domains: set[str] = set()
    for pattern in src_patterns:
        urls = re.findall(pattern, html, re.IGNORECASE)
        for url in urls:
            parsed = re.match(r"https?://([^/]+)", url)
            if parsed:
                domain = parsed.group(1).lower()
                if domain != page_domain:
                    domains.add(domain)
    return len(domains)


def count_obfuscated_js(html: str) -> int:
    """Count obfuscated JavaScript patterns."""
    obfuscation_patterns = [
        r"\beval\s*\(",
        r"\batob\s*\(",
        r"String\.fromCharCode",
        r"\\x[0-9a-fA-F]{2}",
        r"\\u[0-9a-fA-F]{4}",
        r"document\.write\s*\(\s*unescape",
        r"window\[['\"](?:_0x|eval)",
    ]
    count = 0
    for pattern in obfuscation_patterns:
        count += len(re.findall(pattern, html, re.IGNORECASE))
    return count


def check_favicon_mismatch(html: str, page_domain: str) -> bool:
    """Check if favicon domain doesn't match the page domain."""
    favicon_match = re.search(
        r'<link[^>]*rel=["\'](?:shortcut\s+)?icon["\'][^>]*href=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    if not favicon_match:
        return False
    favicon_url = favicon_match.group(1)
    if favicon_url.startswith("/"):
        return False
    parsed = re.match(r"https?://([^/]+)", favicon_url)
    if not parsed:
        return False
    favicon_domain = parsed.group(1).lower()
    return page_domain.lower() not in favicon_domain


def extract_copyright_year(html: str) -> Optional[int]:
    """Extract copyright year from HTML."""
    match = re.search(r"©\s*(\d{4})|copyright\s*(?:\(c\)\s*)?(\d{4})", html, re.IGNORECASE)
    if match:
        year_str = match.group(1) or match.group(2)
        if year_str:
            return int(year_str)
    return None


def analyze_content(html: str, page_domain: str = "") -> dict:
    """Perform full content analysis on HTML."""
    return {
        "login_form_count": count_login_forms(html),
        "password_field_count": count_password_fields(html),
        "credit_card_field_count": count_credit_card_fields(html),
        "brand_mentions": detect_brand_mentions(html),
        "urgency_score": calculate_urgency_score(html),
        "hidden_element_count": count_hidden_elements(html),
        "external_resource_count": count_external_resources(html, page_domain),
        "obfuscated_js_count": count_obfuscated_js(html),
        "favicon_mismatch": check_favicon_mismatch(html, page_domain),
        "copyright_year": extract_copyright_year(html),
    }


def score_content_features(features: dict) -> float:
    """Score content features on a 0-100 scale (higher = more suspicious)."""
    score = 0.0

    if features["login_form_count"] > 0:
        score += features["login_form_count"] * 10
    if features["password_field_count"] > 0:
        score += features["password_field_count"] * 8
    if features["credit_card_field_count"] > 0:
        score += features["credit_card_field_count"] * 15

    if features["brand_mentions"]:
        score += len(features["brand_mentions"]) * 5

    score += features["urgency_score"] * 20

    if features["hidden_element_count"] > 3:
        score += features["hidden_element_count"] * 3

    if features["external_resource_count"] > 5:
        score += features["external_resource_count"] * 2

    if features["obfuscated_js_count"] > 0:
        score += features["obfuscated_js_count"] * 12

    if features["favicon_mismatch"]:
        score += 15

    copyright_year = features.get("copyright_year")
    if copyright_year and copyright_year < 2020:
        score += 10

    return min(100.0, score)
