from __future__ import annotations

from pydantic import BaseModel, Field


class RiskEvidenceInput(BaseModel):
    category: str
    severity: str = "medium"
    contribution: float | None = Field(default=None, ge=0, le=100)
    title: str = ""
    reason: str = ""
    evidence: str | None = None


class RiskCalculationRequest(BaseModel):
    evidence: list[RiskEvidenceInput] = Field(default_factory=list)
    weights: dict[str, float] | None = None
    ai_confidence: float | None = Field(default=None, ge=0, le=1)
    module_availability: dict[str, bool] | None = None


class RiskCalculationResponse(BaseModel):
    risk_score: int
    risk_level: str
    confidence: float
    reasons: list[str]
    category_scores: dict[str, float]
    evidence_count: int
