from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from app.core.config import get_settings

settings = get_settings()


@dataclass
class CircuitBreaker:
    """Circuit breaker pattern for API calls."""

    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    _failure_count: int = 0
    _last_failure_time: float = 0.0
    _state: str = "closed"

    @property
    def state(self) -> str:
        if self._state == "open":
            if time.time() - self._last_failure_time > self.recovery_timeout:
                self._state = "half_open"
        return self._state

    def record_success(self) -> None:
        self._failure_count = 0
        self._state = "closed"

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.time()
        if self._failure_count >= self.failure_threshold:
            self._state = "open"

    @property
    def allow_request(self) -> bool:
        state = self.state
        return state != "open"


_circuit_breaker = CircuitBreaker()

SYSTEM_PROMPT = """You are a cybersecurity expert specializing in phishing detection.
Analyze the provided URL and HTML content for phishing indicators.

Return ONLY a JSON object with these fields:
{
  "is_phishing": boolean,
  "confidence": float (0.0 to 1.0),
  "targeted_brand": string or null,
  "attack_technique": string (e.g., "credential harvesting", "brand impersonation"),
  "signals": [
    {"name": "signal name", "severity": "low"|"medium"|"high"|"critical", "description": "brief explanation"}
  ],
  "reasoning": "1-2 sentence explanation of your analysis"
}

Be precise. Only flag as phishing if you have strong indicators."""


def _build_analysis_prompt(url: str, html_content: Optional[str] = None) -> str:
    """Build the user prompt for GPT-4o analysis."""
    prompt = f"Analyze this URL for phishing: {url}\n"
    if html_content:
        truncated = html_content[:8000]
        prompt += f"\nHTML content (truncated):\n{truncated}"
    return prompt


def _parse_gpt_response(response_text: str) -> dict[str, Any]:
    """Parse GPT-4o JSON response safely."""
    try:
        text = response_text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text)
    except (json.JSONDecodeError, IndexError):
        return {
            "is_phishing": False,
            "confidence": 0.0,
            "targeted_brand": None,
            "attack_technique": "unknown",
            "signals": [],
            "reasoning": "Failed to parse AI response",
        }


async def analyze_with_gpt4o(
    url: str,
    html_content: Optional[str] = None,
    timeout: float = 3.0,
    max_retries: int = 2,
) -> dict[str, Any]:
    """Analyze URL with GPT-4o for phishing detection."""
    if not _circuit_breaker.allow_request:
        return {
            "is_phishing": False,
            "confidence": 0.0,
            "targeted_brand": None,
            "attack_technique": "unknown",
            "signals": [],
            "reasoning": "AI engine unavailable (circuit breaker open)",
            "source": "fallback",
        }

    if not settings.OPENAI_API_KEY:
        return {
            "is_phishing": False,
            "confidence": 0.0,
            "targeted_brand": None,
            "attack_technique": "unknown",
            "signals": [],
            "reasoning": "OpenAI API key not configured",
            "source": "no_api_key",
        }

    user_prompt = _build_analysis_prompt(url, html_content)

    for attempt in range(max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": settings.OPENAI_MODEL,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": user_prompt},
                        ],
                        "temperature": 0.1,
                        "max_tokens": 1000,
                    },
                )
                response.raise_for_status()
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                result = _parse_gpt_response(content)
                result["source"] = "gpt4o"
                _circuit_breaker.record_success()
                return result

        except (httpx.HTTPError, httpx.TimeoutException, KeyError, IndexError):
            _circuit_breaker.record_failure()
            if attempt < max_retries:
                await asyncio.sleep(0.5 * (2**attempt))
            continue

    return {
        "is_phishing": False,
        "confidence": 0.0,
        "targeted_brand": None,
        "attack_technique": "unknown",
        "signals": [],
        "reasoning": "AI analysis failed after retries",
        "source": "fallback",
    }


def score_gpt4_result(gpt4_result: dict[str, Any]) -> float:
    """Convert GPT-4o result to a 0-100 risk score."""
    if not gpt4_result.get("is_phishing"):
        return max(0.0, (1.0 - gpt4_result.get("confidence", 0.5)) * 20)

    confidence = gpt4_result.get("confidence", 0.5)
    base_score = confidence * 80

    signals = gpt4_result.get("signals", [])
    high_signals = sum(1 for s in signals if s.get("severity") in ("high", "critical"))
    base_score += high_signals * 5

    return min(100.0, base_score)
