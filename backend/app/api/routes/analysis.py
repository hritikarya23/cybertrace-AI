from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import require_roles
from app.database.database import get_db
from app.database.models import User
from app.schemas.investigation import AnalysisCreateRequest, AnalysisStartResponse
from app.services.investigation_service import InvestigationServiceError, run_investigation

router = APIRouter(prefix="/api/v1/analysis", tags=["Analysis"])


@router.post("", response_model=AnalysisStartResponse, status_code=201)
async def create_analysis(
    request: AnalysisCreateRequest,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
) -> AnalysisStartResponse:
    """Run the Phase-10 end-to-end passive investigation pipeline."""
    try:
        result = await run_investigation(db, request.email_id, current_user.id)
    except InvestigationServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        # Internal details are intentionally not exposed to clients.
        raise HTTPException(status_code=500, detail="Investigation failed") from exc
    return AnalysisStartResponse(
        analysis_id=result.analysis_id,
        status=result.status,
        classification=result.classification,
        risk_score=result.risk.risk_score,
        risk_level=result.risk.risk_level,
        confidence=result.risk.confidence,
        reasons=result.risk.reasons,
        modules=result.modules,
    )
