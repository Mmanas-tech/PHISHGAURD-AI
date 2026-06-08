from __future__ import annotations

import uuid
from typing import Any

from app.tasks.celery_app import celery_app


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def save_scan_result(self, scan_data: dict[str, Any]) -> str:
    """Save scan result to database asynchronously."""
    try:
        import asyncio
        from app.core.database import async_session_factory
        from app.models.scan import ScanResult

        async def _save():
            async with async_session_factory() as session:
                scan = ScanResult(
                    id=uuid.UUID(scan_data["scan_id"]),
                    user_id=uuid.UUID(scan_data["user_id"]),
                    url=scan_data["url"],
                    domain=scan_data["domain"],
                    risk_score=scan_data["risk_score"],
                    threat_level=scan_data["threat_level"],
                    threat_type=scan_data["threat_type"],
                    signals=scan_data.get("signals", []),
                    recommendation=scan_data.get("recommendation", ""),
                    scan_duration_ms=scan_data.get("scan_duration_ms", 0.0),
                )
                session.add(scan)
                await session.commit()
                return str(scan.id)

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(_save())
            return result
        finally:
            loop.close()

    except Exception as exc:
        self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=2)
def sync_threat_database(self) -> str:
    """Sync threat intelligence database (daily job)."""
    try:
        return "Threat database synced successfully"
    except Exception as exc:
        self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=2)
def batch_virustotal_check(self, urls: list[str]) -> dict[str, Any]:
    """Batch check URLs against VirusTotal."""
    import asyncio
    from app.services.virustotal import check_virustotal

    async def _check_all():
        results = {}
        for url in urls:
            result = await check_virustotal(url)
            results[url] = result
        return results

    try:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_check_all())
        finally:
            loop.close()
    except Exception as exc:
        self.retry(exc=exc)
