from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    html_content: Optional[str] = Field(None, max_length=10_000_000)
    screenshot_b64: Optional[str] = Field(None, max_length=50_000_000)


class ThreatSignalResponse(BaseModel):
    name: str
    severity: str
    description: str = ""
    confidence: float = Field(ge=0.0, le=1.0)


class ScanResponse(BaseModel):
    scan_id: str
    url: str
    domain: str
    risk_score: int = Field(ge=0, le=100)
    threat_level: str
    threat_type: str
    signals: list[ThreatSignalResponse]
    recommendation: str
    is_cached: bool = False
    scan_duration_ms: float = 0.0


class ScanHistoryItem(BaseModel):
    id: str
    url: str
    domain: str
    risk_score: int
    threat_level: str
    threat_type: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanHistoryResponse(BaseModel):
    items: list[ScanHistoryItem]
    total: int
    page: int
    page_size: int
