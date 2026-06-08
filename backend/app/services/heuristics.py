from __future__ import annotations

import math
import re
from typing import Optional
from urllib.parse import urlparse

SUSPICIOUS_TLDS = frozenset(
    [
        "xyz", "top", "club", "online", "site", "website", "space",
        "tech", "info", "biz", "pro", "work", "live", "download",
        "racing", "win", "bid", "stream", "date", "faith", "review",
        "party", "gdn", "loan", "accountant", "cricket", "science",
    ]
)

HOMOGRAPH_MAP: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ɑ": "a", "ɛ": "e", "ɩ": "i", "օ": "o",
    "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e",
    "ꜰ": "f", "ɢ": "g", "ʜ": "h", "ɪ": "i", "ᴊ": "j",
    "ᴋ": "k", "ʟ": "l", "ᴍ": "m", "ɴ": "n", "ᴏ": "o",
    "ᴘ": "p", "ǫ": "q", "ʀ": "r", "ꜱ": "s", "ᴛ": "t",
    "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "x": "x", "ʏ": "y",
    "ᴢ": "z",
}

SUSPICIOUS_KEYWORDS = frozenset(
    [
        "login", "signin", "verify", "account", "update", "secure",
        "banking", "confirm", "password", "credential", "auth",
        "paypal", "apple", "microsoft", "google", "amazon", "netflix",
        "facebook", "instagram", "twitter", "linkedin", "dropbox",
    ]
)

REDIRECT_PARAMS = frozenset(
    ["redirect", "redir", "url", "next", "continue", "return", "goto", "link"]
)


def calculate_entropy(domain: str) -> float:
    """Calculate Shannon entropy of a domain string."""
    if not domain:
        return 0.0
    freq: dict[str, int] = {}
    for char in domain:
        freq[char] = freq.get(char, 0) + 1
    length = len(domain)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def check_homograph_attack(domain: str) -> tuple[bool, list[str]]:
    """Detect Unicode homograph attacks in domain."""
    detected: list[str] = []
    for char in domain:
        if char in HOMOGRAPH_MAP:
            detected.append(f"'{char}' → '{HOMOGRAPH_MAP[char]}'")
    return len(detected) > 0, detected


def check_typosquatting(
    domain: str, legitimate_domains: Optional[list[str]] = None
) -> Optional[str]:
    """Check if domain is a typosquatting variant of a known brand."""
    if legitimate_domains is None:
        legitimate_domains = []

    base_domain = domain.split(".")[0].lower()
    for legit in legitimate_domains:
        legit_base = legit.split(".")[0].lower()
        if base_domain == legit_base:
            continue
        distance = _levenshtein(base_domain, legit_base)
        if 1 <= distance <= 2 and len(legit_base) > 3:
            return legit
    return None


def _levenshtein(s1: str, s2: str) -> int:
    """Calculate Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def check_suspicious_tld(domain: str) -> str:
    """Check if domain uses a suspicious TLD."""
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return "unknown"
    tld = parts[-1]
    if tld in SUSPICIOUS_TLDS:
        return "high"
    if len(tld) > 4 or tld.isdigit():
        return "medium"
    return "low"


def check_redirect_chain(url: str) -> tuple[str, list[str]]:
    """Parse URL for redirect parameters. Returns final URL and hop indicators."""
    parsed = urlparse(url)
    hops: list[str] = []
    query = parsed.query.lower()
    for param in REDIRECT_PARAMS:
        if param in query:
            hops.append(param)
    return url, hops


def check_brand_impersonation(
    url: str, html_content: Optional[str] = None
) -> Optional[str]:
    """Detect if URL or content impersonates a known brand."""
    domain = urlparse(url).netloc.lower()
    content_lower = html_content.lower() if html_content else ""

    brand_indicators = {
        "paypal": ["paypal", "paypa1", "paypaI"],
        "apple": ["apple", "app1e", "appIe"],
        "microsoft": ["microsoft", "micr0soft", "micrοsoft"],
        "google": ["google", "g00gle", "goog1e"],
        "amazon": ["amazon", "amaz0n", "amazn"],
        "netflix": ["netflix", "netf1ix", "netfliix"],
        "facebook": ["facebook", "faceb00k", "facebοοk"],
        "instagram": ["instagram", "instagrarn", "instagran"],
    }

    for brand, indicators in brand_indicators.items():
        for indicator in indicators:
            if indicator in domain and brand not in domain:
                return brand
            if html_content and indicator in content_lower:
                if brand not in domain:
                    return brand
    return None


def extract_domain_features(url: str) -> dict:
    """Extract all URL-based heuristic features."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path

    has_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain.split(":")[0]))
    has_port = ":" in domain and not domain.endswith(":443") and not domain.endswith(":80")

    subdomain_parts = domain.split(".")
    num_subdomains = max(0, len(subdomain_parts) - 2)

    has_at = "@" in url
    has_redirect = any(p in parsed.query.lower() for p in REDIRECT_PARAMS)
    path_depth = len([p for p in path.split("/") if p])

    suspicious_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]

    return {
        "url_length": len(url),
        "num_subdomains": num_subdomains,
        "num_hyphens": domain.count("-"),
        "num_digits": sum(c.isdigit() for c in domain),
        "has_ip_address": has_ip,
        "has_port": has_port,
        "uses_https": parsed.scheme == "https",
        "has_at_symbol": has_at,
        "domain_entropy": calculate_entropy(domain),
        "path_depth": path_depth,
        "has_redirect_params": has_redirect,
        "suspicious_keywords": suspicious_kw,
    }


def score_url_heuristics(features: dict) -> float:
    """Score URL features on a 0-100 scale (higher = more suspicious)."""
    score = 0.0

    if features["url_length"] > 75:
        score += min(15, (features["url_length"] - 75) * 0.5)
    if features["url_length"] > 150:
        score += 10

    if features["num_subdomains"] > 2:
        score += features["num_subdomains"] * 5
    if features["num_hyphens"] > 2:
        score += features["num_hyphens"] * 3
    if features["num_digits"] > 4:
        score += features["num_digits"] * 2

    if features["has_ip_address"]:
        score += 25
    if features["has_port"]:
        score += 10
    if features["has_at_symbol"]:
        score += 20
    if not features["uses_https"]:
        score += 15

    if features["domain_entropy"] > 4.0:
        score += 15
    if features["domain_entropy"] > 5.0:
        score += 10

    if features["has_redirect_params"]:
        score += 10

    score += len(features["suspicious_keywords"]) * 5

    tld_risk = check_suspicious_tld(
        features.get("_domain", "")
    )
    if tld_risk == "high":
        score += 20
    elif tld_risk == "medium":
        score += 10

    is_homo, homo_chars = check_homograph_attack(features.get("_domain", ""))
    if is_homo:
        score += 30

    return min(100.0, score)
