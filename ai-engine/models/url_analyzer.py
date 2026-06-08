from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

SUSPICIOUS_TLDS = frozenset([
    "xyz", "top", "club", "online", "site", "website", "space",
    "tech", "info", "biz", "pro", "work", "live", "download",
    "racing", "win", "bid", "stream", "date", "faith", "review",
    "party", "gdn", "loan", "accountant", "cricket", "science",
    "click", "fit", "loan", "webcam", "tokyo", "buzz", "gq",
])

HOMOGRAPH_CHARS = frozenset([
    "а", "е", "о", "р", "с", "у", "х", "і", "ј", "ѕ",
    "ɑ", "ɛ", "ɩ", "օ", "ᴀ", "ʙ", "ᴄ", "ᴅ", "ᴇ",
    "ꜰ", "ɢ", "ʜ", "ɪ", "ᴊ", "ᴋ", "ʟ", "ᴍ", "ɴ",
    "ᴏ", "ᴘ", "ǫ", "ʀ", "ꜱ", "ᴛ", "ᴜ", "ᴠ", "ᴡ", "ʏ", "ᴢ",
])

TOP_BRANDS = [
    "google", "facebook", "amazon", "microsoft", "apple", "netflix",
    "paypal", "twitter", "instagram", "linkedin", "dropbox", "github",
    "yahoo", "ebay", "reddit", "wikipedia", "tiktok", "snapchat",
    "twitch", "discord", "spotify", "uber", "airbnb", "zoom",
]

SUSPICIOUS_KEYWORDS = frozenset([
    "login", "signin", "verify", "account", "update", "secure",
    "banking", "confirm", "password", "credential", "auth",
    "wallet", "crypto", "defi", "nft", "token", "airdrop",
])

REDIRECT_PARAMS = frozenset([
    "redirect", "redir", "url", "next", "continue", "return", "goto", "link",
])


@dataclass
class URLFeatures:
    """Extracted URL features for phishing detection."""
    url_length: int = 0
    num_subdomains: int = 0
    num_hyphens: int = 0
    num_digits: int = 0
    has_ip_address: bool = False
    has_port: bool = False
    uses_https: bool = False
    has_at_symbol: bool = False
    domain_entropy: float = 0.0
    tld_risk_score: float = 0.0
    homograph_score: float = 0.0
    levenshtein_distance: int = 0
    path_depth: int = 0
    has_redirect_params: bool = False
    suspicious_keywords: list[str] = field(default_factory=list)
    domain_age_days: Optional[int] = None
    certificate_valid: Optional[bool] = None
    certificate_issuer: Optional[str] = None
    domain_name_length: int = 0
    has_double_slash_in_path: bool = False
    has_data_uri: bool = False
    num_dots_in_domain: int = 0
    has_hex_chars: bool = False
    url_entropy: float = 0.0


def _calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
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


def _min_brand_distance(domain: str) -> int:
    """Calculate minimum Levenshtein distance to any top brand."""
    base = domain.split(".")[0].lower()
    min_dist = len(base)
    for brand in TOP_BRANDS:
        dist = _levenshtein_distance(base, brand)
        if dist < min_dist:
            min_dist = dist
    return min_dist


class URLAnalyzer:
    """Extract and score URL-based features for phishing detection."""

    def analyze(self, url: str) -> URLFeatures:
        """Analyze a URL and extract all features."""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path
        features = URLFeatures()

        features.url_length = len(url)
        features.uses_https = parsed.scheme == "https"
        features.has_at_symbol = "@" in url
        features.has_port = ":" in domain and not domain.endswith(
            ":443"
        ) and not domain.endswith(":80")

        ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        features.has_ip_address = bool(ip_pattern.match(domain.split(":")[0]))

        subdomain_parts = domain.split(".")
        features.num_subdomains = max(0, len(subdomain_parts) - 2)
        features.num_dots_in_domain = domain.count(".")

        features.num_hyphens = domain.count("-")
        features.num_digits = sum(c.isdigit() for c in domain)

        features.domain_entropy = _calculate_shannon_entropy(domain)
        features.url_entropy = _calculate_shannon_entropy(url)
        features.domain_name_length = len(domain.split(".")[0])

        tld = subdomain_parts[-1] if len(subdomain_parts) >= 2 else ""
        if tld in SUSPICIOUS_TLDS:
            features.tld_risk_score = 0.9
        elif len(tld) > 4 or tld.isdigit():
            features.tld_risk_score = 0.5
        else:
            features.tld_risk_score = 0.1

        homo_count = sum(1 for c in domain if c in HOMOGRAPH_CHARS)
        features.homograph_score = min(1.0, homo_count / max(len(domain), 1))

        features.levenshtein_distance = _min_brand_distance(domain)

        path_parts = [p for p in path.split("/") if p]
        features.path_depth = len(path_parts)

        query_lower = parsed.query.lower()
        features.has_redirect_params = any(
            p in query_lower for p in REDIRECT_PARAMS
        )

        url_lower = url.lower()
        features.suspicious_keywords = [
            kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower
        ]

        features.has_double_slash_in_path = (
            "//" in path and not url.startswith("http")
        )
        features.has_data_uri = "data:" in url_lower

        has_hex = bool(re.search(r"%[0-9a-fA-F]{2}", url))
        features.has_hex_chars = has_hex

        return features

    def score(self, features: URLFeatures) -> float:
        """Score URL features on a 0-100 risk scale."""
        score = 0.0

        if features.url_length > 75:
            score += min(12, (features.url_length - 75) * 0.3)
        if features.url_length > 150:
            score += 8

        if features.num_subdomains > 2:
            score += features.num_subdomains * 4
        if features.num_hyphens > 2:
            score += features.num_hyphens * 3
        if features.num_digits > 4:
            score += features.num_digits * 2

        if features.has_ip_address:
            score += 25
        if features.has_port:
            score += 8
        if features.has_at_symbol:
            score += 20
        if not features.uses_https:
            score += 15

        if features.domain_entropy > 4.0:
            score += 12
        if features.domain_entropy > 5.0:
            score += 8

        score += features.tld_risk_score * 15
        score += features.homograph_score * 30

        if features.levenshtein_distance == 1:
            score += 20
        elif features.levenshtein_distance == 2:
            score += 10

        if features.has_redirect_params:
            score += 8
        if features.has_double_slash_in_path:
            score += 10
        if features.has_hex_chars:
            score += 5

        score += len(features.suspicious_keywords) * 4

        return min(100.0, max(0.0, score))
