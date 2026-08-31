from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import require_roles
from app.database.database import get_db
from app.database.models import Email, User
from app.schemas.ai import AIAnalysisResponse, AIIndicatorResponse
from app.services.ai_service import analyze_text

router = APIRouter(prefix="/api/v1/emails", tags=["AI Analysis"])


@router.post("/{email_id}/ai", response_model=AIAnalysisResponse)
async def analyze_email_ai(
    email_id: int,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
) -> AIAnalysisResponse:
    """Analyze email subject/body through the configured local or external AI service."""
    email = await db.scalar(select(Email).where(Email.id == email_id, Email.user_id == current_user.id))
    if email is None:
        raise HTTPException(status_code=404, detail="Email not found")

    result = await analyze_text(email.subject, email.body_text or email.body_html)
    return AIAnalysisResponse(
        email_id=email_id,
        classification=result.classification,
        confidence=result.confidence,
        phishing_probability=result.phishing_probability,
        indicators=[AIIndicatorResponse(type=i.type, description=i.description) for i in result.indicators],
        status=result.status,
        source=result.source,
        mock=result.mock,
        reason=result.reason,
    )
