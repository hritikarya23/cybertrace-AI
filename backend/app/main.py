from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.auth import router as auth_router
from app.api.routes.emails import router as emails_router
from app.api.routes.intelligence import router as intelligence_router
from app.api.routes.ai import router as ai_router
from app.api.routes.risk import router as risk_router
from app.api.routes.analysis import router as analysis_router
from app.api.routes.investigations import router as investigations_router
from app.api.routes.graph import router as graph_router
from app.api.routes.reports import router as reports_router
from app.config import settings
from app.database.database import dispose_engine


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    await dispose_engine()


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    description="REST API for AI-powered email threat detection and forensic investigation.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)
app.include_router(auth_router)
app.include_router(emails_router)
app.include_router(intelligence_router)
app.include_router(ai_router)
app.include_router(risk_router)
app.include_router(analysis_router)
app.include_router(investigations_router)
app.include_router(graph_router)
app.include_router(reports_router)


@app.get("/api/v1/health", tags=["Health"])
async def health() -> dict[str, str]:
    return {"status": "healthy", "version": "1.0.0"}
