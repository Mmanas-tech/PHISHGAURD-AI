from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ai_engine.models.url_analyzer import URLAnalyzer, URLFeatures
from ai_engine.models.content_analyzer import ContentAnalyzer, ContentFeatures
from ai_engine.models.gpt4_analyzer import GPT4PhishingAnalyzer


@dataclass
class EnsembleScore:
    """Final ensemble score with breakdown."""
    final_score: int = 0
    url_heuristic_score: float = 0.0
    content_analysis_score: float = 0.0
    gpt4_score: float = 0.0
    virustotal_score: float = 0.0
    domain_reputation_score: float = 0.0
    override_triggered: bool = False
    override_reason: Optional[str] = None


class EnsembleScorer:
    """Weighted ensemble scoring with override rules."""

    WEIGHTS = {
        "url_heuristic": 0.25,
        "content_analysis": 0.20,
        "gpt4": 0.30,
        "virustotal": 0.15,
        "domain_reputation": 0.10,
    }

    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.content_analyzer = ContentAnalyzer()

    def score(
        self,
        url: str,
        html_content: Optional[str] = None,
        gpt4_result: Optional[dict[str, Any]] = None,
        vt_result: Optional[dict[str, Any]] = None,
        domain_age_days: Optional[int] = None,
    ) -> EnsembleScore:
        """Calculate weighted ensemble risk score."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        url_features = self.url_analyzer.analyze(url)
        url_score = self.url_analyzer.score(url_features)

        content_features: Optional[ContentFeatures] = None
        content_score = 0.0
        if html_content:
            content_features = self.content_analyzer.analyze(html_content, domain)
            content_score = self.content_analyzer.score(content_features)

        gpt4_score = 0.0
        gpt4_analyzer = GPT4PhishingAnalyzer(api_key="")
        if gpt4_result:
            gpt4_score = gpt4_analyzer.score(gpt4_result)

        vt_score = 0.0
        if vt_result:
            if vt_result.get("status") not in ("no_api_key", "error", "submit_failed"):
                vt_score = min(100.0, vt_result.get("score", 0.0))

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
            url_score * self.WEIGHTS["url_heuristic"]
            + content_score * self.WEIGHTS["content_analysis"]
            + gpt4_score * self.WEIGHTS["gpt4"]
            + vt_score * self.WEIGHTS["virustotal"]
            + domain_rep_score * self.WEIGHTS["domain_reputation"]
        )

        override_triggered = False
        override_reason: Optional[str] = None

        if vt_result and vt_result.get("detection_count", 0) >= 2:
            override_triggered = True
            override_reason = "Multiple VirusTotal engines flagged this URL"
            final_score = max(final_score, 90.0)

        if domain_age_days is not None and domain_age_days < 1:
            has_login = False
            if content_features:
                has_login = (
                    content_features.password_field_count > 0
                    or content_features.login_form_count > 0
                )
            if has_login:
                override_triggered = True
                override_reason = "Domain <24 hours old with login form"
                final_score = max(final_score, 95.0)

        if url_features.homograph_score > 0.3:
            override_triggered = True
            override_reason = "Unicode homograph attack detected"
            final_score = max(final_score, 95.0)

        has_password = False
        if content_features:
            has_password = (
                content_features.password_field_count > 0
                or content_features.login_form_count > 0
            )
        if has_password and parsed.scheme != "https":
            override_triggered = True
            override_reason = "HTTP page with password field"
            final_score = max(final_score, 85.0)

        final_score = min(100.0, max(0.0, final_score))

        return EnsembleScore(
            final_score=int(final_score),
            url_heuristic_score=round(url_score, 2),
            content_analysis_score=round(content_score, 2),
            gpt4_score=round(gpt4_score, 2),
            virustotal_score=round(vt_score, 2),
            domain_reputation_score=round(domain_rep_score, 2),
            override_triggered=override_triggered,
            override_reason=override_reason,
        )

    def determine_threat_level(self, score: int) -> str:
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
        self,
        score: int,
        gpt4_result: Optional[dict[str, Any]] = None,
        content_features: Optional[ContentFeatures] = None,
        url_features: Optional[URLFeatures] = None,
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
            if content_features.credit_card_field_count > 0:
                return "financial_fraud"
            if content_features.login_form_count > 0:
                return "credential_theft"

        if url_features:
            if url_features.has_ip_address:
                return "phishing"
            if url_features.num_hyphens > 3:
                return "typosquatting"

        return "unknown"
