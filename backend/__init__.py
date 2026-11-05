"""CyberShield Backend Package.

Provides the FastAPI application, REST route handlers, Pydantic schemas,
and dependency injection services.
"""

from backend.api import app, create_app

__all__ = ["app", "create_app"]
