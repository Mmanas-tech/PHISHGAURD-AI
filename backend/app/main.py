import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.database import close_db, init_db
from app.core.redis import close_redis
from app.routers import auth_router, dashboard_router, scan_router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: startup and shutdown."""
    await init_db()
    yield
    await close_db()
    await close_redis()


app = FastAPI(
    title=settings.APP_NAME,
    description="Real-time AI-powered phishing detection API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Add request ID for distributed tracing."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    start_time = time.time()

    response = await call_next(request)

    duration = (time.time() - start_time) * 1000
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time"] = f"{duration:.2f}ms"

    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Global exception handler returning RFC 7807 Problem JSON."""
    return JSONResponse(
        status_code=500,
        content={
            "type": "about:blank",
            "title": "Internal Server Error",
            "status": 500,
            "detail": str(exc) if settings.DEBUG else "An unexpected error occurred",
        },
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={
            "type": "about:blank",
            "title": "Not Found",
            "status": 404,
            "detail": "The requested resource was not found",
        },
    )


@app.exception_handler(422)
async def validation_error_handler(request: Request, exc) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "type": "about:blank",
            "title": "Validation Error",
            "status": 422,
            "detail": str(exc),
        },
    )


app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(dashboard_router)


@app.get("/health", tags=["system"])
async def health_check() -> dict:
    """Health check endpoint with DB + cache status."""
    db_status = "ok"
    cache_status = "ok" if settings.USE_REDIS else "in-memory"

    try:
        from sqlalchemy import text
        from app.core.database import engine

        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        db_status = "error"

    if settings.USE_REDIS:
        try:
            from app.core.redis import _get_redis_client

            r = await _get_redis_client()
            if r:
                await r.ping()
            else:
                cache_status = "unavailable"
        except Exception:
            cache_status = "error"

    status_ok = db_status == "ok"

    return {
        "status": "healthy" if status_ok else "degraded",
        "version": "1.0.0",
        "services": {
            "database": db_status,
            "cache": cache_status,
        },
    }


@app.get("/metrics", tags=["system"])
async def metrics() -> dict:
    """Prometheus metrics endpoint (placeholder)."""
    return {
        "scan_requests_total": 0,
        "scan_duration_seconds_p50": 0.0,
        "scan_duration_seconds_p95": 0.0,
        "scan_duration_seconds_p99": 0.0,
        "ai_engine_errors_total": 0,
        "active_connections": 0,
    }
