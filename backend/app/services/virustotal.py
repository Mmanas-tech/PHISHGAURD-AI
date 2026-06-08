from __future__ import annotations

import asyncio
from typing import Any, Optional

import httpx

from app.core.config import get_settings

settings = get_settings()


async def check_virustotal(
    url: str, timeout: float = 5.0
) -> dict[str, Any]:
    """Check URL against VirusTotal API v3."""
    if not settings.VIRUSTOTAL_API_KEY:
        return {
            "source": "virustotal",
            "status": "no_api_key",
            "detection_count": 0,
            "total_engines": 0,
            "score": 0.0,
            "categories": [],
            "error": None,
        }

    encoded_url = url.replace(":", "%3A").replace("/", "%2F")
    api_url = f"{settings.VIRUSTOTAL_API_URL}/urls/{encoded_url}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                api_url,
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )

            if response.status_code == 404:
                return await _submit_and_check(url, timeout)

            response.raise_for_status()
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            categories = []
            for engine, result in attributes.get("last_analysis_results", {}).items():
                if result.get("category") in ("malicious", "suspicious"):
                    categories.append(result.get("result", "unknown"))

            score = (malicious / total * 100) if total > 0 else 0.0

            return {
                "source": "virustotal",
                "status": "found",
                "detection_count": malicious,
                "total_engines": total,
                "score": round(score, 2),
                "categories": categories[:10],
                "error": None,
            }

    except httpx.HTTPError as e:
        return {
            "source": "virustotal",
            "status": "error",
            "detection_count": 0,
            "total_engines": 0,
            "score": 0.0,
            "categories": [],
            "error": str(e),
        }


async def _submit_and_check(
    url: str, timeout: float = 5.0
) -> dict[str, Any]:
    """Submit URL for scanning and retrieve results."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            submit_response = await client.post(
                f"{settings.VIRUSTOTAL_API_URL}/urls",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                data={"url": url},
            )
            submit_response.raise_for_status()
            analysis_id = submit_response.json().get("data", {}).get("id")

            if not analysis_id:
                return {
                    "source": "virustotal",
                    "status": "submit_failed",
                    "detection_count": 0,
                    "total_engines": 0,
                    "score": 0.0,
                    "categories": [],
                    "error": "No analysis ID returned",
                }

            await asyncio.sleep(2.0)

            analysis_response = await client.get(
                f"{settings.VIRUSTOTAL_API_URL}/analyses/{analysis_id}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
            analysis_response.raise_for_status()
            attrs = analysis_response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("results", {})

            malicious = 0
            total = 0
            categories: list[str] = []
            for engine, result in stats.items():
                total += 1
                if result.get("category") in ("malicious", "suspicious"):
                    malicious += 1
                    categories.append(result.get("result", "unknown"))

            score = (malicious / total * 100) if total > 0 else 0.0

            return {
                "source": "virustotal",
                "status": "analyzed",
                "detection_count": malicious,
                "total_engines": total,
                "score": round(score, 2),
                "categories": categories[:10],
                "error": None,
            }

    except httpx.HTTPError as e:
        return {
            "source": "virustotal",
            "status": "error",
            "detection_count": 0,
            "total_engines": 0,
            "score": 0.0,
            "categories": [],
            "error": str(e),
        }


def score_virustotal(vt_result: dict[str, Any]) -> float:
    """Convert VirusTotal result to a 0-100 risk score."""
    if vt_result.get("status") in ("no_api_key", "error", "submit_failed"):
        return 0.0
    return min(100.0, vt_result.get("score", 0.0))
