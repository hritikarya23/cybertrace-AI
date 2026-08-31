from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user, require_roles
from app.database.database import get_db
from app.database.models import User
from app.services.report_service import generate_report

router = APIRouter(prefix="/api/v1/investigations", tags=["Reports"])


@router.get("/{analysis_id}/report/html")
async def get_html_report(
    analysis_id: int,
    user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    result = await generate_report(db, analysis_id, user.id, user.full_name, "html")
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    path, _ = result
    return FileResponse(path, media_type="text/html", filename=path.name)


@router.get("/{analysis_id}/report/pdf")
async def get_pdf_report(
    analysis_id: int,
    user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    result = await generate_report(db, analysis_id, user.id, user.full_name, "pdf")
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    path, _ = result
    return FileResponse(path, media_type="application/pdf", filename=path.name)
