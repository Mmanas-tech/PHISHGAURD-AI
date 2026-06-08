from __future__ import annotations

import os
import time
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ai_engine.pipelines.detection_pipeline import DetectionPipeline

app = FastAPI(
    title="PhishGuard AI Engine",
    description="Zero-day phishing detection ML pipeline",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pipeline = DetectionPipeline(
    openai_api_key=os.getenv("OPENAI_API_KEY", ""),
    virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
)


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    html_content: Optional[str] = Field(None, max_length=10_000_000)


class SignalResponse(BaseModel):
    name: str
    severity: str
    description: str
    confidence: float


class ScanResponse(BaseModel):
    scan_id: str
    url: str
    domain: str
    risk_score: int
    threat_level: str
    threat_type: str
    signals: list[SignalResponse]
    recommendation: str
    scan_duration_ms: float
    ensemble_breakdown: dict[str, Any]


@app.get("/health")
async def health_check() -> dict:
    return {"status": "healthy", "version": "1.0.0"}


@app.post("/api/v1/analyze", response_model=ScanResponse)
async def analyze_url(request: ScanRequest) -> ScanResponse:
    """Analyze a URL for phishing threats."""
    try:
        result = await pipeline.scan(
            url=request.url,
            html_content=request.html_content,
        )

        signals = [
            SignalResponse(
                name=s["name"],
                severity=s["severity"],
                description=s.get("description", ""),
                confidence=s.get("confidence", 0.5),
            )
            for s in result.signals
        ]

        return ScanResponse(
            scan_id=result.scan_id,
            url=result.url,
            domain=result.domain,
            risk_score=result.risk_score,
            threat_level=result.threat_level,
            threat_type=result.threat_type,
            signals=signals,
            recommendation=result.recommendation,
            scan_duration_ms=result.scan_duration_ms,
            ensemble_breakdown=result.ensemble_breakdown,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/metrics")
async def metrics() -> dict:
    return {
        "scans_total": 0,
        "avg_duration_ms": 0.0,
        "error_rate": 0.0,
    }
