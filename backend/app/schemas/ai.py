from __future__ import annotations

from pydantic import BaseModel, Field


class AIIndicatorResponse(BaseModel):
    type: str
    description: str


class AIAnalysisResponse(BaseModel):
    email_id: int
    classification: str
    confidence: float = Field(ge=0, le=1)
    phishing_probability: float = Field(ge=0, le=1)
    indicators: list[AIIndicatorResponse]
    status: str
    source: str
    mock: bool
    reason: str | None = None
