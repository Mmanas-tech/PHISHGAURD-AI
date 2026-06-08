from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Optional

from ai_engine.models.url_analyzer import URLAnalyzer
from ai_engine.models.content_analyzer import ContentAnalyzer
from ai_engine.models.gpt4_analyzer import GPT4PhishingAnalyzer
from ai_engine.ensemble.scorer import EnsembleScorer


@dataclass
class ScanResult:
    """Complete scan result from the detection pipeline."""
    scan_id: str
    url: str
    domain: str
    risk_score: int
    threat_level: str
    threat_type: str
    signals: list[dict[str, Any]]
    recommendation: str
    scan_duration_ms: float
    ensemble_breakdown: dict[str, Any]


class DetectionPipeline:
    """Orchestrates all detection components."""

    def __init__(
        self,
        openai_api_key: str = "",
        virustotal_api_key: str = "",
    ):
        self.url_analyzer = URLAnalyzer()
        self.content_analyzer = ContentAnalyzer()
        self.gpt4_analyzer = GPT4PhishingAnalyzer(api_key=openai_api_key)
        self.ensemble_scorer = EnsembleScorer()
        self.openai_api_key = openai_api_key
        self.virustotal_api_key = virustotal_api_key

    async def scan(
        self,
        url: str,
        html_content: Optional[str] = None,
    ) -> ScanResult:
        """Run full detection pipeline."""
        import uuid
        from urllib.parse import urlparse

        scan_id = str(uuid.uuid4())
        start_time = time.time()
        domain = urlparse(url).netloc.lower()

        url_features = self.url_analyzer.analyze(url)

        tasks = [
            self._run_gpt4_analysis(url, html_content),
            self._run_virustotal_check(url),
        ]
        gpt4_result, vt_result = await asyncio.gather(
            *tasks, return_exceptions=True
        )

        if isinstance(gpt4_result, Exception):
            gpt4_result = None
        if isinstance(vt_result, Exception):
            vt_result = None

        content_features = None
        if html_content:
            content_features = self.content_analyzer.analyze(html_content, domain)

        ensemble_result = self.ensemble_scorer.score(
            url=url,
            html_content=html_content,
            gpt4_result=gpt4_result,
            vt_result=vt_result,
        )

        signals = self._build_signals(
            url_features, content_features, gpt4_result, ensemble_result
        )

        threat_level = self.ensemble_scorer.determine_threat_level(
            ensemble_result.final_score
        )
        threat_type = self.ensemble_scorer.determine_threat_type(
            ensemble_result.final_score,
            gpt4_result,
            content_features,
            url_features,
        )
        recommendation = self._generate_recommendation(
            threat_level, signals
        )

        scan_duration_ms = (time.time() - start_time) * 1000

        return ScanResult(
            scan_id=scan_id,
            url=url,
            domain=domain,
            risk_score=ensemble_result.final_score,
            threat_level=threat_level,
            threat_type=threat_type,
            signals=signals,
            recommendation=recommendation,
            scan_duration_ms=round(scan_duration_ms, 2),
            ensemble_breakdown={
                "url_heuristic_score": ensemble_result.url_heuristic_score,
                "content_analysis_score": ensemble_result.content_analysis_score,
                "gpt4_score": ensemble_result.gpt4_score,
                "virustotal_score": ensemble_result.virustotal_score,
                "domain_reputation_score": ensemble_result.domain_reputation_score,
                "override_triggered": ensemble_result.override_triggered,
                "override_reason": ensemble_result.override_reason,
            },
        )

    async def _run_gpt4_analysis(
        self, url: str, html_content: Optional[str]
    ) -> Optional[dict[str, Any]]:
        try:
            return await self.gpt4_analyzer.analyze(url, html_content)
        except Exception:
            return None

    async def _run_virustotal_check(self, url: str) -> Optional[dict[str, Any]]:
        if not self.virustotal_api_key:
            return {"status": "no_api_key", "detection_count": 0, "score": 0.0}
        try:
            import httpx

            async with httpx.AsyncClient(timeout=5.0) as client:
                encoded_url = url.replace(":", "%3A").replace("/", "%2F")
                response = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
                    headers={"x-apikey": self.virustotal_api_key},
                )
                if response.status_code == 200:
                    data = response.json()
                    stats = (
                        data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    )
                    malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 0
                    score = (malicious / total * 100) if total > 0 else 0.0
                    return {
                        "status": "found",
                        "detection_count": malicious,
                        "total_engines": total,
                        "score": round(score, 2),
                    }
                return {"status": "not_found", "detection_count": 0, "score": 0.0}
        except Exception:
            return {"status": "error", "detection_count": 0, "score": 0.0}

    def _build_signals(
        self, url_features, content_features, gpt4_result, ensemble_result
    ) -> list[dict[str, Any]]:
        signals: list[dict[str, Any]] = []

        if url_features.has_ip_address:
            signals.append({
                "name": "IP Address URL",
                "severity": "high",
                "description": "Domain is an IP address instead of a hostname",
                "confidence": 0.95,
            })
        if url_features.has_at_symbol:
            signals.append({
                "name": "At Symbol in URL",
                "severity": "medium",
                "description": "URL contains @ symbol which can hide the real domain",
                "confidence": 0.8,
            })
        if url_features.num_hyphens > 2:
            signals.append({
                "name": "Excessive Hyphens",
                "severity": "medium",
                "description": f"Domain contains {url_features.num_hyphens} hyphens",
                "confidence": 0.6,
            })
        if url_features.domain_entropy > 4.5:
            signals.append({
                "name": "High Entropy Domain",
                "severity": "medium",
                "description": "Domain name has unusually high entropy",
                "confidence": 0.7,
            })
        if not url_features.uses_https:
            signals.append({
                "name": "No HTTPS",
                "severity": "medium",
                "description": "Site does not use HTTPS encryption",
                "confidence": 0.85,
            })
        if url_features.suspicious_keywords:
            kw = ", ".join(url_features.suspicious_keywords[:3])
            signals.append({
                "name": "Suspicious Keywords",
                "severity": "medium",
                "description": f"URL contains suspicious keywords: {kw}",
                "confidence": 0.75,
            })
        if url_features.homograph_score > 0.3:
            signals.append({
                "name": "Homograph Attack",
                "severity": "critical",
                "description": "Domain uses Unicode lookalike characters",
                "confidence": 0.95,
            })

        if content_features:
            if content_features.password_field_count > 0:
                signals.append({
                    "name": "Password Field Detected",
                    "severity": "high",
                    "description": "Page contains password input fields",
                    "confidence": 0.9,
                })
            if content_features.credit_card_field_count > 0:
                signals.append({
                    "name": "Credit Card Field",
                    "severity": "critical",
                    "description": "Page contains credit card input fields",
                    "confidence": 0.95,
                })
            if content_features.obfuscated_js_count > 0:
                signals.append({
                    "name": "Obfuscated JavaScript",
                    "severity": "high",
                    "description": "Page contains obfuscated JavaScript code",
                    "confidence": 0.8,
                })
            if content_features.favicon_mismatch:
                signals.append({
                    "name": "Favicon Mismatch",
                    "severity": "medium",
                    "description": "Favicon is hosted on a different domain",
                    "confidence": 0.7,
                })
            if content_features.urgency_score > 0.5:
                signals.append({
                    "name": "Urgency Language",
                    "severity": "medium",
                    "description": "Page uses urgency/scare tactics",
                    "confidence": 0.6,
                })
            if content_features.iframe_count > 3:
                signals.append({
                    "name": "Multiple Iframes",
                    "severity": "medium",
                    "description": f"Page contains {content_features.iframe_count} iframes",
                    "confidence": 0.65,
                })

        if gpt4_result and gpt4_result.get("signals"):
            for sig in gpt4_result["signals"]:
                signals.append({
                    "name": sig.get("name", "AI Detection"),
                    "severity": sig.get("severity", "medium"),
                    "description": sig.get("description", ""),
                    "confidence": gpt4_result.get("confidence", 0.5),
                })

        return signals

    def _generate_recommendation(
        self, threat_level: str, signals: list[dict]
    ) -> str:
        if threat_level == "safe":
            return "This site appears safe. No phishing indicators detected."
        if threat_level == "critical":
            return (
                "BLOCK THIS SITE IMMEDIATELY. Multiple critical phishing indicators "
                "detected. Do not enter any personal information."
            )
        if threat_level == "high":
            return (
                "High risk of phishing detected. Proceed with extreme caution or "
                "avoid this site entirely."
            )
        if threat_level == "medium":
            return (
                "Moderate risk detected. Verify the site's legitimacy before "
                "entering any information."
            )
        return (
            "Low risk detected. Minor suspicious indicators found. "
            "Exercise normal caution."
        )
