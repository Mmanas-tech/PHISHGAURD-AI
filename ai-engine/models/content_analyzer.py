from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ContentFeatures:
    """Extracted HTML content features for phishing detection."""
    login_form_count: int = 0
    password_field_count: int = 0
    credit_card_field_count: int = 0
    brand_mentions: list[str] = field(default_factory=list)
    urgency_score: float = 0.0
    hidden_element_count: int = 0
    external_resource_count: int = 0
    obfuscated_js_count: int = 0
    favicon_mismatch: bool = False
    copyright_year: Optional[int] = None
    has_base64_images: bool = False
    form_action_count: int = 0
    iframe_count: int = 0
    meta_refresh_count: int = 0
    javascript_href_count: int = 0
    external_css_count: int = 0
    email_in_form: bool = False
    popup_count: int = 0


BRAND_INDICATORS = {
    "paypal": ["paypal", "paypa1", "paypai", "xpaypal"],
    "apple": ["apple", "app1e", "appIe", "appie"],
    "microsoft": ["microsoft", "micr0soft", "micrоsoft"],
    "google": ["google", "g00gle", "goog1e", "googIe"],
    "amazon": ["amazon", "amaz0n", "amazn", "arnazon"],
    "netflix": ["netflix", "netf1ix", "netfIix"],
    "facebook": ["facebook", "faceb00k", "facebооk"],
    "instagram": ["instagram", "instagrarn", "instagran"],
    "twitter": ["twitter", "twiiter", "twitt3r"],
    "linkedin": ["linkedin", "linkedln", "1inkedin"],
    "dropbox": ["dropbox", "dr0pbox", "dropb0x"],
    "github": ["github", "gith0b", "githuub"],
}

URGENCY_PATTERNS = [
    re.compile(r"act\s+now", re.IGNORECASE),
    re.compile(r"immediate(ly)?", re.IGNORECASE),
    re.compile(r"urgent", re.IGNORECASE),
    re.compile(r"expires?\s+(today|soon|now)", re.IGNORECASE),
    re.compile(r"limited\s+time", re.IGNORECASE),
    re.compile(r"last\s+chance", re.IGNORECASE),
    re.compile(r"don'?t\s+miss", re.IGNORECASE),
    re.compile(r"verify\s+(your|account|identity)", re.IGNORECASE),
    re.compile(r"confirm\s+(your|account|identity)", re.IGNORECASE),
    re.compile(r"account\s+(suspended|locked|compromised)", re.IGNORECASE),
    re.compile(r"unauthorized\s+(access|activity)", re.IGNORECASE),
    re.compile(r"security\s+(alert|warning|breach)", re.IGNORECASE),
    re.compile(r"click\s+(here|immediately|now)", re.IGNORECASE),
    re.compile(r"your\s+account\s+will\s+be", re.IGNORECASE),
    re.compile(r"failure\s+to\s+(verify|confirm|act)", re.IGNORECASE),
]

OBFUSCATION_PATTERNS = [
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\batob\s*\(", re.IGNORECASE),
    re.compile(r"String\.fromCharCode", re.IGNORECASE),
    re.compile(r"\\x[0-9a-fA-F]{2}"),
    re.compile(r"\\u[0-9a-fA-F]{4}"),
    re.compile(r"document\.write\s*\(\s*unescape", re.IGNORECASE),
    re.compile(r"window\[['\"](?:_0x|eval)", re.IGNORECASE),
    re.compile(r"Function\s*\(\s*['\"]return", re.IGNORECASE),
    re.compile(r"setTimeout\s*\(\s*['\"]", re.IGNORECASE),
]


class ContentAnalyzer:
    """Analyze HTML content for phishing indicators."""

    def analyze(self, html: str, page_domain: str = "") -> ContentFeatures:
        """Perform full content analysis on HTML."""
        features = ContentFeatures()

        features.login_form_count = self._count_login_forms(html)
        features.password_field_count = self._count_password_fields(html)
        features.credit_card_field_count = self._count_credit_card_fields(html)
        features.brand_mentions = self._detect_brand_mentions(html)
        features.urgency_score = self._calculate_urgency_score(html)
        features.hidden_element_count = self._count_hidden_elements(html)
        features.external_resource_count = self._count_external_resources(
            html, page_domain
        )
        features.obfuscated_js_count = self._count_obfuscated_js(html)
        features.favicon_mismatch = self._check_favicon_mismatch(html, page_domain)
        features.copyright_year = self._extract_copyright_year(html)
        features.has_base64_images = bool(
            re.search(r'<img[^>]*src=["\']data:image/', html, re.IGNORECASE)
        )
        features.form_action_count = len(
            re.findall(r"<form[^>]*action=", html, re.IGNORECASE)
        )
        features.iframe_count = len(
            re.findall(r"<iframe[^>]*>", html, re.IGNORECASE)
        )
        features.meta_refresh_count = len(
            re.findall(
                r'<meta[^>]*http-equiv=["\']refresh["\']', html, re.IGNORECASE
            )
        )
        features.javascript_href_count = len(
            re.findall(r'href=["\']javascript:', html, re.IGNORECASE)
        )
        features.external_css_count = len(
            re.findall(
                r'<link[^>]*href=["\']https?://[^"\']+\.css', html, re.IGNORECASE
            )
        )
        features.email_in_form = bool(
            re.search(
                r'<input[^>]*type=["\']email["\'][^>]*>', html, re.IGNORECASE
            )
        )
        features.popup_count = len(
            re.findall(r"window\.open\s*\(", html, re.IGNORECASE)
        )

        return features

    def _count_login_forms(self, html: str) -> int:
        password_fields = self._count_password_fields(html)
        login_inputs = len(
            re.findall(
                r'<input[^>]*(?:name|id|placeholder)=["\'][^"\']*(?:login|email|user)[^"\']*["\'][^>]*>',
                html,
                re.IGNORECASE,
            )
        )
        return max(password_fields, login_inputs)

    def _count_password_fields(self, html: str) -> int:
        return len(
            re.findall(
                r'<input[^>]*type=["\']password["\'][^>]*>', html, re.IGNORECASE
            )
        )

    def _count_credit_card_fields(self, html: str) -> int:
        patterns = [
            r'<input[^>]*(?:name|id|placeholder)=["\'][^"\']*(?:cc|credit|card|cvv|cvc|pan)[^"\']*["\'][^>]*>',
            r'<input[^>]*autocomplete=["\'][^"\']*(?:cc-|credit-card)[^"\']*["\'][^>]*>',
        ]
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, html, re.IGNORECASE))
        return count

    def _detect_brand_mentions(self, html: str) -> list[str]:
        html_lower = html.lower()
        return [
            brand
            for brand, indicators in BRAND_INDICATORS.items()
            if any(ind in html_lower for ind in indicators)
        ]

    def _calculate_urgency_score(self, html: str) -> float:
        count = sum(
            1 for pattern in URGENCY_PATTERNS if pattern.search(html)
        )
        return min(1.0, count / 5.0)

    def _count_hidden_elements(self, html: str) -> int:
        patterns = [
            r'<div[^>]*style=["\'][^"\']*display\s*:\s*none[^"\']*["\'][^>]*>.*?</div>',
            r'<div[^>]*style=["\'][^"\']*visibility\s*:\s*hidden[^"\']*["\'][^>]*>.*?</div>',
            r'<input[^>]*type=["\']hidden["\'][^>]*>',
        ]
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, html, re.IGNORECASE | re.DOTALL))
        return count

    def _count_external_resources(self, html: str, page_domain: str) -> int:
        src_patterns = [r'(?:src|href|action)=["\']?(https?://[^"\s\'<>]+)']
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

    def _count_obfuscated_js(self, html: str) -> int:
        count = 0
        for pattern in OBFUSCATION_PATTERNS:
            count += len(re.findall(pattern, html))
        return count

    def _check_favicon_mismatch(self, html: str, page_domain: str) -> bool:
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

    def _extract_copyright_year(self, html: str) -> Optional[int]:
        match = re.search(
            r"©\s*(\d{4})|copyright\s*(?:\(c\)\s*)?(\d{4})", html, re.IGNORECASE
        )
        if match:
            year_str = match.group(1) or match.group(2)
            if year_str:
                return int(year_str)
        return None

    def score(self, features: ContentFeatures) -> float:
        """Score content features on a 0-100 risk scale."""
        score = 0.0

        if features.login_form_count > 0:
            score += features.login_form_count * 10
        if features.password_field_count > 0:
            score += features.password_field_count * 8
        if features.credit_card_field_count > 0:
            score += features.credit_card_field_count * 15

        if features.brand_mentions:
            score += len(features.brand_mentions) * 5

        score += features.urgency_score * 20

        if features.hidden_element_count > 3:
            score += features.hidden_element_count * 3

        if features.external_resource_count > 5:
            score += features.external_resource_count * 2

        if features.obfuscated_js_count > 0:
            score += features.obfuscated_js_count * 12

        if features.favicon_mismatch:
            score += 15

        if features.iframe_count > 3:
            score += features.iframe_count * 4

        if features.meta_refresh_count > 0:
            score += features.meta_refresh_count * 8

        if features.javascript_href_count > 0:
            score += features.javascript_href_count * 10

        if features.has_base64_images:
            score += 5

        copyright_year = features.copyright_year
        if copyright_year and copyright_year < 2020:
            score += 10

        return min(100.0, max(0.0, score))
