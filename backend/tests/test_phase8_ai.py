import pytest

from app.services.ai_service import analyze_text


@pytest.mark.asyncio
async def test_legacy_mock_flag_does_not_fabricate_ai_results(monkeypatch):
    monkeypatch.setenv("MOCK_EXTERNAL_SERVICES", "true")
    result = await analyze_text("Urgent account verification", "Please verify your password immediately.")
    assert result.mock is False
    assert result.source == "none"
    assert result.status == "unavailable"
    assert result.classification == "unknown"
    assert result.indicators == []


@pytest.mark.asyncio
async def test_unconfigured_ai_is_unavailable(monkeypatch):
    monkeypatch.delenv("MOCK_EXTERNAL_SERVICES", raising=False)
    monkeypatch.delenv("AI_LOCAL_MODEL_PATH", raising=False)
    monkeypatch.delenv("AI_SERVICE_URL", raising=False)
    result = await analyze_text("hello", "normal message")
    assert result.status == "unavailable"
    assert result.mock is False
    assert result.source == "none"
