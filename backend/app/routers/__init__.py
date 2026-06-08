from app.routers.auth import router as auth_router
from app.routers.scan import router as scan_router
from app.routers.dashboard import router as dashboard_router

__all__ = ["auth_router", "scan_router", "dashboard_router"]
