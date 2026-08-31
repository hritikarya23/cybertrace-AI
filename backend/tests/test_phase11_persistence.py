from datetime import datetime, timezone

import pytest
from app.database.models import Analysis
from app.services.persistence_service import persist_analysis_result


class FakeSession:
    def __init__(self):
        self.added = []
        self.deleted = []

    async def execute(self, statement):
        self.deleted.append(statement)

    def add_all(self, rows):
        self.added.extend(rows)

    async def flush(self):
        return None


@pytest.mark.asyncio
async def test_persist_analysis_clamps_scores_and_sets_completion():
    session = FakeSession()
    analysis = Analysis(email_id=1, classification="unknown", status="processing")
    analysis.id = 10
    result = await persist_analysis_result(
        session, analysis,
        classification="phishing", risk_score=120, confidence=-0.2,
        summary="high risk", indicators=[{
            "category": "url", "severity": "high", "title": "Suspicious URL",
            "description": "test", "evidence": "https://example.test", "score": 20,
        }],
    )
    assert result.status == "completed"
    assert result.risk_score == 100
    assert result.confidence == 0.0
    assert result.completed_at is not None
    assert len(session.added) == 1

@pytest.mark.asyncio
async def test_persist_analysis_creates_no_indicators_for_empty_input():
    session = FakeSession()
    analysis = Analysis(email_id=1, classification="unknown", status="processing")
    analysis.id = 11
    await persist_analysis_result(
        session, analysis, classification="unknown", risk_score=0,
        confidence=0.5, summary="clean", indicators=[],
    )
    assert session.added == []
