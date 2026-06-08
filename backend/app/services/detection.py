from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Optional
from urllib.parse import urlparse

import json

from app.core.config import get_settings
from app.core.redis import cache_get, cache_set
from app.services.ai_analyzer import analyze_with_gpt4o
from app.services.content_analyzer import analyze_content
from app.services.ensemble import (
    calculate_ensemble_score,
    determine_threat_level,
    determine_threat_type,
    generate_recommendation,
)
from app.services.heuristics import extract_domain_features
from app.services.virustotal import check_virustotal

settings = get_settings()


def _extract_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(url)
    return parsed.netloc.lower()


def _build_cache_key(url: str) -> str:
    """Build Redis cache key for a URL."""
    return f"scan:{url}"


def _build_signals(
    ensemble_result: dict[str, Any],
    gpt4_result: Optional[dict[str, Any]],
    content_features: Optional[dict],
    url_features: Optional[dict],
) -> list[dict[str, Any]]:
    """Build signals list from analysis results."""
    signals: list[dict[str, Any]] = []

    if url_features:
        if url_features.get("has_ip_address"):
            signals.append({
                "name": "IP Address URL",
                "severity": "high",
                "description": "Domain is an IP address instead of a hostname",
                "confidence": 0.95,
            })
        if url_features.get("has_at_symbol"):
            signals.append({
                "name": "At Symbol in URL",
                "severity": "medium",
                "description": "URL contains @ symbol which can hide the real domain",
                "confidence": 0.8,
            })
        if url_features.get("num_hyphens", 0) > 2:
            signals.append({
                "name": "Excessive Hyphens",
                "severity": "medium",
                "description": f"Domain contains {url_features['num_hyphens']} hyphens",
                "confidence": 0.6,
            })
        if url_features.get("domain_entropy", 0) > 4.5:
            signals.append({
                "name": "High Entropy Domain",
                "severity": "medium",
                "description": "Domain name has unusually high entropy",
                "confidence": 0.7,
            })
        if not url_features.get("uses_https"):
            signals.append({
                "name": "No HTTPS",
                "severity": "medium",
                "description": "Site does not use HTTPS encryption",
                "confidence": 0.85,
            })
        if url_features.get("suspicious_keywords"):
            kw = ", ".join(url_features["suspicious_keywords"][:3])
            signals.append({
                "name": "Suspicious Keywords",
                "severity": "medium",
                "description": f"URL contains suspicious keywords: {kw}",
                "confidence": 0.75,
            })

    if content_features:
        if content_features.get("password_field_count", 0) > 0:
            signals.append({
                "name": "Password Field Detected",
                "severity": "high",
                "description": "Page contains password input fields",
                "confidence": 0.9,
            })
        if content_features.get("credit_card_field_count", 0) > 0:
            signals.append({
                "name": "Credit Card Field",
                "severity": "critical",
                "description": "Page contains credit card input fields",
                "confidence": 0.95,
            })
        if content_features.get("obfuscated_js_count", 0) > 0:
            signals.append({
                "name": "Obfuscated JavaScript",
                "severity": "high",
                "description": "Page contains obfuscated JavaScript code",
                "confidence": 0.8,
            })
        if content_features.get("favicon_mismatch"):
            signals.append({
                "name": "Favicon Mismatch",
                "severity": "medium",
                "description": "Favicon is hosted on a different domain",
                "confidence": 0.7,
            })
        if content_features.get("urgency_score", 0) > 0.5:
            signals.append({
                "name": "Urgency Language",
                "severity": "medium",
                "description": "Page uses urgency/scare tactics",
                "confidence": 0.6,
            })
        if content_features.get("hidden_element_count", 0) > 5:
            signals.append({
                "name": "Hidden Elements",
                "severity": "medium",
                "description": f"Page has {content_features['hidden_element_count']} hidden elements",
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


async def scan_url(
    url: str,
    html_content: Optional[str] = None,
    screenshot_b64: Optional[str] = None,
) -> dict[str, Any]:
    """Perform full URL scan with parallel analysis."""
    start_time = time.time()
    scan_id = str(uuid.uuid4())

    cache_key = _build_cache_key(url)
    cached = await cache_get(cache_key)
    if cached:
        try:
            result = json.loads(cached)
            result["is_cached"] = True
            return result
        except (json.JSONDecodeError, TypeError):
            pass

    domain = _extract_domain(url)
    url_features = extract_domain_features(url)

    tasks = [
        analyze_with_gpt4o(url, html_content),
        check_virustotal(url),
    ]

    gpt4_result, vt_result = await asyncio.gather(*tasks, return_exceptions=True)

    if isinstance(gpt4_result, Exception):
        gpt4_result = {
            "is_phishing": False,
            "confidence": 0.0,
            "signals": [],
            "reasoning": str(gpt4_result),
            "source": "error",
        }
    if isinstance(vt_result, Exception):
        vt_result = {
            "status": "error",
            "detection_count": 0,
            "total_engines": 0,
            "score": 0.0,
            "error": str(vt_result),
        }

    content_features = None
    if html_content:
        content_features = analyze_content(html_content, domain)

    ensemble_result = calculate_ensemble_score(
        url=url,
        html_content=html_content,
        gpt4_result=gpt4_result,
        vt_result=vt_result,
    )

    signals = _build_signals(ensemble_result, gpt4_result, content_features, url_features)

    threat_level = determine_threat_level(ensemble_result["final_score"])
    threat_type = determine_threat_type(
        ensemble_result["final_score"], gpt4_result, content_features, url_features
    )
    recommendation = generate_recommendation(
        ensemble_result["final_score"], threat_level, signals
    )

    scan_duration_ms = (time.time() - start_time) * 1000

    result = {
        "scan_id": scan_id,
        "url": url,
        "domain": domain,
        "risk_score": ensemble_result["final_score"],
        "threat_level": threat_level,
        "threat_type": threat_type,
        "signals": signals,
        "recommendation": recommendation,
        "is_cached": False,
        "scan_duration_ms": round(scan_duration_ms, 2),
        "ensemble_breakdown": ensemble_result,
    }

    try:
        await cache_set(cache_key, json.dumps(result, default=str), ttl=300)
    except Exception:
        pass

    return result
