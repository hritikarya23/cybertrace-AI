"""
Health check endpoint.

Used by load balancers, container orchestrators, and the frontend to
verify the API is up. Deliberately has zero dependencies (no DB, no
external services) in this phase so it always reflects "is the process
alive and serving requests" — later phases may add a `/health/full`
endpoint that also checks DB/AI service connectivity.
"""

from fastapi import APIRouter

from app import __version__
from app.config import get_settings

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Basic liveness check")
async def health_check() -> dict:
    settings = get_settings()
    return {
        "success": True,
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "version": __version__,
        "environment": settings.APP_ENV,
    }
