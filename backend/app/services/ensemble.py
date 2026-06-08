from __future__ import annotations

from typing import Any, Optional

from app.services.heuristics import (
    check_brand_impersonation,
    check_homograph_attack,
    extract_domain_features,
    score_url_heuristics,
)
from app.services.content_analyzer import analyze_content, score_content_features
from app.services.ai_analyzer import score_gpt4_result
from app.services.virustotal import score_virustotal


def calculate_ensemble_score(
    url: str,
    html_content: Optional[str] = None,
    gpt4_result: Optional[dict[str, Any]] = None,
    vt_result: Optional[dict[str, Any]] = None,
    domain_age_days: Optional[int] = None,
) -> dict[str, Any]:
    """Calculate weighted ensemble risk score with override rules."""

    from urllib.parse import urlparse

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    url_features = extract_domain_features(url)
    url_features["_domain"] = domain
    url_score = score_url_heuristics(url_features)

    content_score = 0.0
    content_features: dict[str, Any] = {}
    if html_content:
        content_features = analyze_content(html_content, domain)
        content_score = score_content_features(content_features)

    gpt4_score = 0.0
    if gpt4_result:
        gpt4_score = score_gpt4_result(gpt4_result)

    vt_score = score_virustotal(vt_result) if vt_result else 0.0

    domain_rep_score = 0.0
    if domain_age_days is not None:
        if domain_age_days < 1:
            domain_rep_score = 80.0
        elif domain_age_days < 7:
            domain_rep_score = 60.0
        elif domain_age_days < 30:
            domain_rep_score = 40.0
        elif domain_age_days < 90:
            domain_rep_score = 20.0

    final_score = (
        url_score * 0.25
        + content_score * 0.20
        + gpt4_score * 0.30
        + vt_score * 0.15
        + domain_rep_score * 0.10
    )

    override_triggered = False
    override_reason: Optional[str] = None

    if vt_result and vt_result.get("detection_count", 0) >= 2:
        override_triggered = True
        override_reason = "Multiple VirusTotal engines flagged this URL"
        final_score = max(final_score, 90.0)

    if domain_age_days is not None and domain_age_days < 1:
        has_login = content_features.get("password_field_count", 0) > 0
        has_login = has_login or content_features.get("login_form_count", 0) > 0
        if has_login:
            override_triggered = True
            override_reason = "Domain <24 hours old with login form"
            final_score = max(final_score, 95.0)

    is_homo, homo_chars = check_homograph_attack(domain)
    if is_homo:
        override_triggered = True
        override_reason = f"Unicode homograph attack detected: {', '.join(homo_chars)}"
        final_score = max(final_score, 95.0)

    has_password = (
        content_features.get("password_field_count", 0) > 0
        or content_features.get("login_form_count", 0) > 0
    )
    if has_password and parsed.scheme != "https":
        override_triggered = True
        override_reason = "HTTP page with password field"
        final_score = max(final_score, 85.0)

    final_score = min(100.0, max(0.0, final_score))

    return {
        "final_score": int(final_score),
        "url_heuristic_score": round(url_score, 2),
        "content_analysis_score": round(content_score, 2),
        "gpt4_score": round(gpt4_score, 2),
        "virustotal_score": round(vt_score, 2),
        "domain_reputation_score": round(domain_rep_score, 2),
        "override_triggered": override_triggered,
        "override_reason": override_reason,
    }


def determine_threat_level(score: int) -> str:
    """Map numeric score to threat level."""
    if score < 20:
        return "safe"
    elif score < 40:
        return "low"
    elif score < 60:
        return "medium"
    elif score < 80:
        return "high"
    else:
        return "critical"


def determine_threat_type(
    score: int,
    gpt4_result: Optional[dict[str, Any]] = None,
    content_features: Optional[dict] = None,
    url_features: Optional[dict] = None,
) -> str:
    """Determine the specific threat type."""
    if gpt4_result and gpt4_result.get("is_phishing"):
        technique = gpt4_result.get("attack_technique", "").lower()
        if "credential" in technique:
            return "credential_theft"
        if "brand" in technique or "impersonation" in technique:
            return "brand_impersonation"
        if "social" in technique:
            return "social_engineering"
        return "phishing"

    if content_features:
        if content_features.get("credit_card_field_count", 0) > 0:
            return "financial_fraud"
        if content_features.get("login_form_count", 0) > 0:
            return "credential_theft"

    if url_features:
        if url_features.get("has_ip_address"):
            return "phishing"
        if url_features.get("num_hyphens", 0) > 3:
            return "typosquatting"

    return "unknown"


def generate_recommendation(
    score: int, threat_level: str, signals: list[dict]
) -> str:
    """Generate a human-readable recommendation."""
    if threat_level == "safe":
        return "This site appears safe. No phishing indicators detected."

    signal_names = [s.get("name", "") for s in signals]

    if threat_level == "critical":
        return (
            "BLOCK THIS SITE IMMEDIATELY. Multiple critical phishing indicators detected. "
            "Do not enter any personal information."
        )

    if threat_level == "high":
        parts = ["High risk of phishing detected."]
        if "homograph_attack" in signal_names:
            parts.append("This domain uses Unicode characters to impersonate a legitimate site.")
        if "suspicious_tld" in signal_names:
            parts.append("The domain uses a suspicious top-level domain.")
        parts.append("Proceed with extreme caution or avoid this site entirely.")
        return " ".join(parts)

    if threat_level == "medium":
        return (
            "Moderate risk detected. Some suspicious indicators found. "
            "Verify the site's legitimacy before entering any information."
        )

    return (
        "Low risk detected. Minor suspicious indicators found. "
        "Exercise normal caution."
    )
