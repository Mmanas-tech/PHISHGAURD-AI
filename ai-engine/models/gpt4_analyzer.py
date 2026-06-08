from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx


@dataclass
class CircuitBreaker:
    """Circuit breaker for API calls."""

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
        return self.state != "open"


SYSTEM_PROMPT = """You are a cybersecurity expert specializing in phishing detection.
Analyze the provided URL and HTML content for phishing indicators.

Return ONLY a JSON object with these fields:
{
  "is_phishing": boolean,
  "confidence": float (0.0 to 1.0),
  "targeted_brand": string or null,
  "attack_technique": string (e.g., "credential harvesting", "brand impersonation", "social engineering"),
  "signals": [
    {"name": "signal name", "severity": "low"|"medium"|"high"|"critical", "description": "brief explanation"}
  ],
  "reasoning": "1-2 sentence explanation of your analysis"
}

Be precise. Only flag as phishing if you have strong indicators.
Do not flag legitimate sites as phishing. Focus on:
- Fake login pages impersonating brands
- Credential harvesting forms
- Suspicious redirects
- Domain impersonation techniques
- Social engineering tactics"""


class GPT4PhishingAnalyzer:
    """GPT-4o powered phishing analysis with circuit breaker."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        timeout: float = 3.0,
        max_retries: int = 2,
    ):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self._circuit_breaker = CircuitBreaker()

    def _build_prompt(self, url: str, html_content: Optional[str] = None) -> str:
        prompt = f"Analyze this URL for phishing: {url}\n"
        if html_content:
            truncated = html_content[:8000]
            prompt += f"\nHTML content (truncated):\n{truncated}"
        return prompt

    def _parse_response(self, response_text: str) -> dict[str, Any]:
        try:
            text = response_text.strip()
            if text.startswith("```"):
                parts = text.split("```")
                text = parts[1] if len(parts) > 1 else text
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

    async def analyze(
        self, url: str, html_content: Optional[str] = None
    ) -> dict[str, Any]:
        """Analyze URL with GPT-4o for phishing detection."""
        if not self._circuit_breaker.allow_request:
            return {
                "is_phishing": False,
                "confidence": 0.0,
                "targeted_brand": None,
                "attack_technique": "unknown",
                "signals": [],
                "reasoning": "AI engine unavailable (circuit breaker open)",
                "source": "fallback",
            }

        if not self.api_key:
            return {
                "is_phishing": False,
                "confidence": 0.0,
                "targeted_brand": None,
                "attack_technique": "unknown",
                "signals": [],
                "reasoning": "OpenAI API key not configured",
                "source": "no_api_key",
            }

        user_prompt = self._build_prompt(url, html_content)

        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {self.api_key}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": self.model,
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
                    result = self._parse_response(content)
                    result["source"] = "gpt4o"
                    self._circuit_breaker.record_success()
                    return result

            except (httpx.HTTPError, httpx.TimeoutException, KeyError, IndexError):
                self._circuit_breaker.record_failure()
                if attempt < self.max_retries:
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

    def score(self, gpt4_result: dict[str, Any]) -> float:
        """Convert GPT-4o result to a 0-100 risk score."""
        if not gpt4_result.get("is_phishing"):
            return max(0.0, (1.0 - gpt4_result.get("confidence", 0.5)) * 20)

        confidence = gpt4_result.get("confidence", 0.5)
        base_score = confidence * 80

        signals = gpt4_result.get("signals", [])
        high_signals = sum(
            1 for s in signals if s.get("severity") in ("high", "critical")
        )
        base_score += high_signals * 5

        return min(100.0, base_score)
