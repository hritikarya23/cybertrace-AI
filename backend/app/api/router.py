"""
Top-level API router for version 1 of the API.

Individual route modules (health, auth, emails, analysis, ...) register
themselves here. This is the single object main.py mounts under the
API_V1_PREFIX, so adding a new route module in a later phase means:
  1. create app/api/routes/<name>.py with its own `router = APIRouter()`
  2. import it below and include it with `api_router.include_router(...)`
"""

from fastapi import APIRouter

from app.api.routes import health

api_router = APIRouter()

api_router.include_router(health.router)

# Registered in later phases as each module is implemented:
# api_router.include_router(auth.router)
# api_router.include_router(emails.router)
# api_router.include_router(analysis.router)
# api_router.include_router(investigations.router)
# api_router.include_router(reports.router)
# api_router.include_router(graph.router)
