from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import require_roles
from app.database.models import User
from app.schemas.risk import RiskCalculationRequest, RiskCalculationResponse
from app.services.risk_engine import RiskEvidence, calculate_risk

router = APIRouter(prefix="/api/v1/risk", tags=["Risk Scoring"])


@router.post("/calculate", response_model=RiskCalculationResponse)
async def calculate_risk_api(
    request: RiskCalculationRequest,
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> RiskCalculationResponse:
    """Calculate a transparent 0-100 risk score from supplied forensic evidence."""
    try:
        evidence = [RiskEvidence(**item.model_dump()) for item in request.evidence]
        result = calculate_risk(
            evidence,
            weights=request.weights,
            ai_confidence=request.ai_confidence,
            module_availability=request.module_availability,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return RiskCalculationResponse(
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        confidence=result.confidence,
        reasons=result.reasons,
        category_scores=result.category_scores,
        evidence_count=result.evidence_count,
    )
