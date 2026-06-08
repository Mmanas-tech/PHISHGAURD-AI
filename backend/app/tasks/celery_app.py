from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "phishguard",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "sync-threat-database": {
            "task": "app.tasks.scan_task.sync_threat_database",
            "schedule": 86400.0,
        },
    },
)
