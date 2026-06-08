import json
import re
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_active_user, rate_limit_default
from app.models.scan import ScanResult
from app.models.user import User
from app.schemas.scan import (
    ScanHistoryItem,
    ScanHistoryResponse,
    ScanRequest,
    ScanResponse,
    ThreatSignalResponse,
)
from app.services.detection import scan_url

router = APIRouter(prefix="/api/v1/scan", tags=["scan"])

VALID_URL_PATTERN = re.compile(
    r"^https?://[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*(/\S*)?$"
)


def _validate_url(url: str) -> str:
    """Validate and sanitize URL."""
    url = url.strip()
    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="URL is required"
        )
    if len(url) > 2048:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="URL too long (max 2048 chars)"
        )
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid URL format"
        )
    if not VALID_URL_PATTERN.match(url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid URL format"
        )
    return url


@router.post("", response_model=ScanResponse)
async def create_scan(
    request: Request,
    scan_req: ScanRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    _rate: None = Depends(rate_limit_default),
) -> ScanResponse:
    """Scan a URL for phishing threats."""
    validated_url = _validate_url(scan_req.url)

    result = await scan_url(
        url=validated_url,
        html_content=scan_req.html_content,
        screenshot_b64=scan_req.screenshot_b64,
    )

    signals_data = [
        ThreatSignalResponse(
            name=s["name"],
            severity=s["severity"],
            description=s.get("description", ""),
            confidence=s.get("confidence", 0.5),
        )
        for s in result.get("signals", [])
    ]

    scan_record = ScanResult(
        user_id=current_user.id,
        url=result["url"],
        domain=result["domain"],
        risk_score=result["risk_score"],
        threat_level=result["threat_level"],
        threat_type=result["threat_type"],
        signals=[s.model_dump() for s in signals_data],
        recommendation=result["recommendation"],
        scan_duration_ms=result["scan_duration_ms"],
    )
    db.add(scan_record)
    await db.flush()

    return ScanResponse(
        scan_id=result["scan_id"],
        url=result["url"],
        domain=result["domain"],
        risk_score=result["risk_score"],
        threat_level=result["threat_level"],
        threat_type=result["threat_type"],
        signals=signals_data,
        recommendation=result["recommendation"],
        is_cached=result.get("is_cached", False),
        scan_duration_ms=result["scan_duration_ms"],
    )


@router.get("/history", response_model=ScanHistoryResponse)
async def get_scan_history(
    page: int = 1,
    page_size: int = 20,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ScanHistoryResponse:
    """Get scan history for the current user."""
    offset = (page - 1) * page_size

    count_query = select(func.count()).select_from(ScanResult).where(
        ScanResult.user_id == current_user.id
    )
    total = (await db.execute(count_query)).scalar() or 0

    query = (
        select(ScanResult)
        .where(ScanResult.user_id == current_user.id)
        .order_by(ScanResult.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(query)
    scans = result.scalars().all()

    items = [
        ScanHistoryItem(
            id=s.id,
            url=s.url,
            domain=s.domain,
            risk_score=s.risk_score,
            threat_level=s.threat_level,
            threat_type=s.threat_type,
            created_at=s.created_at,
        )
        for s in scans
    ]

    return ScanHistoryResponse(
        items=items, total=total, page=page, page_size=page_size
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    """Get a specific scan result."""
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.id == scan_id,
            ScanResult.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )

    signals = scan.signals if isinstance(scan.signals, list) else []
    signal_responses = [
        ThreatSignalResponse(
            name=s.get("name", ""),
            severity=s.get("severity", "medium"),
            description=s.get("description", ""),
            confidence=s.get("confidence", 0.5),
        )
        for s in signals
    ]

    return ScanResponse(
        scan_id=str(scan.id),
        url=scan.url,
        domain=scan.domain,
        risk_score=scan.risk_score,
        threat_level=scan.threat_level,
        threat_type=scan.threat_type,
        signals=signal_responses,
        recommendation=scan.recommendation,
        is_cached=False,
        scan_duration_ms=scan.scan_duration_ms,
    )
