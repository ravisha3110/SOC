"""CyberShield API Route Handlers."""

from backend.routes.auth import router as auth_router
from backend.routes.files import router as files_router
from backend.routes.health import router as health_router
from backend.routes.network import router as network_router
from backend.routes.scans import router as scans_router
from backend.routes.sync import router as sync_router
from backend.routes.threats import router as threats_router
from backend.routes.urls import router as urls_router

__all__ = [
    "auth_router",
    "health_router",
    "scans_router",
    "threats_router",
    "files_router",
    "urls_router",
    "network_router",
    "sync_router",
]

