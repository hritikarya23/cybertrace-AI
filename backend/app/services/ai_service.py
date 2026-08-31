from __future__ import annotations

import importlib
import os
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx


@dataclass(slots=True)
class AIIndicator:
    type: str
    description: str


@dataclass(slots=True)
class AIResult:
    classification: str
    confidence: float
    phishing_probability: float
    indicators: list[AIIndicator] = field(default_factory=list)
    status: str = "unavailable"
    source: str = "none"
    mock: bool = False
    reason: str | None = None


_ALLOWED = {"legitimate", "phishing", "spoofing", "malware", "fraud", "suspicious", "unknown"}


def _clamp(value: Any, low: float = 0.0, high: float = 1.0) -> float:
    try:
        return max(low, min(high, float(value)))
    except (TypeError, ValueError):
        return low


def _normalize(raw: dict[str, Any], source: str, *, mock: bool = False) -> AIResult:
    classification = str(raw.get("classification", "unknown")).lower()
    if classification not in _ALLOWED:
        classification = "unknown"
    probability = _clamp(raw.get("phishing_probability", raw.get("confidence", 0.0)))
    confidence = _clamp(raw.get("confidence", probability))
    indicators: list[AIIndicator] = []
    for item in raw.get("indicators", []) or []:
        if isinstance(item, dict):
            indicators.append(AIIndicator(
                type=str(item.get("type", "unknown")),
                description=str(item.get("description", "AI indicator detected")),
            ))
    return AIResult(
        classification=classification,
        confidence=confidence,
        phishing_probability=probability,
        indicators=indicators,
        status="completed",
        source=source,
        mock=mock,
        reason=None,
    )


def _load_local_model() -> Callable[[str, str], dict[str, Any]] | None:
    """Load a local model adapter from AI_LOCAL_MODEL_PATH=module:function."""
    target = os.getenv("AI_LOCAL_MODEL_PATH", "").strip()
    if not target:
        return None
    module_name, sep, function_name = target.partition(":")
    if not sep or not module_name or not function_name:
        raise ValueError("AI_LOCAL_MODEL_PATH must use module:function format")
    module = importlib.import_module(module_name)
    fn = getattr(module, function_name, None)
    if not callable(fn):
        raise ValueError("Configured local AI adapter is not callable")
    return fn


async def _external(text_subject: str, text_body: str) -> AIResult:
    url = os.getenv("AI_SERVICE_URL", "").strip()
    if not url:
        return AIResult("unknown", 0.0, 0.0, status="unavailable", reason="AI service not configured")
    headers = {}
    key = os.getenv("AI_SERVICE_API_KEY", "").strip()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    timeout = float(os.getenv("AI_SERVICE_TIMEOUT_SECONDS", "8"))
    payload = {"subject": text_subject, "body": text_body}
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("AI service returned a non-object response")
            return _normalize(data, "external")
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        return AIResult("unknown", 0.0, 0.0, status="unavailable", reason=f"External AI unavailable: {type(exc).__name__}")


def _mock(subject: str, body: str) -> AIResult:
    # Deterministic demo-only output. It is explicitly marked mock and is never presented as real intelligence.
    text = f"{subject}\n{body}".lower()
    indicators: list[AIIndicator] = []
    if any(word in text for word in ("urgent", "immediately", "act now")):
        indicators.append(AIIndicator("urgency", "Urgency-oriented language detected"))
    if any(word in text for word in ("password", "credential", "verify your account", "login")):
        indicators.append(AIIndicator("credential_request", "Possible credential verification request"))
    if any(word in text for word in ("gift card", "wire transfer", "bank account")):
        indicators.append(AIIndicator("financial_request", "Possible financial request detected"))
    probability = min(0.95, 0.20 + 0.25 * len(indicators))
    classification = "phishing" if probability >= 0.7 else "suspicious" if probability >= 0.45 else "legitimate"
    return AIResult(classification, probability, probability, indicators, "completed", "mock", True)


async def analyze_text(subject: str | None, body: str | None) -> AIResult:
    """Run configured AI analysis; never fabricate results when a real provider is unavailable."""
    subject = subject or ""
    body = body or ""
    if os.getenv("MOCK_EXTERNAL_SERVICES", "false").strip().lower() in {"1", "true", "yes", "on"}:
        return _mock(subject, body)

    local_path = os.getenv("AI_LOCAL_MODEL_PATH", "").strip()
    if local_path:
        try:
            fn = _load_local_model()
            raw = fn(subject, body) if fn else None
            if not isinstance(raw, dict):
                raise ValueError("Local AI adapter must return a dictionary")
            return _normalize(raw, "local")
        except Exception as exc:
            # Local model failure should not stop the rest of the forensic pipeline.
            return AIResult("unknown", 0.0, 0.0, status="unavailable", reason=f"Local AI unavailable: {type(exc).__name__}")

    return await _external(subject, body)
