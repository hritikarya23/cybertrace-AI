from __future__ import annotations

from pydantic import BaseModel, Field


class AnalysisCreateRequest(BaseModel):
    email_id: int = Field(gt=0)


class AnalysisStartResponse(BaseModel):
    analysis_id: int
    status: str
    classification: str
    risk_score: int
    risk_level: str
    confidence: float
    reasons: list[str]
    modules: dict[str, bool]
