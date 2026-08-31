from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


DEFAULT_WEIGHTS = {
    "ai_nlp": 30.0,
    "authentication_header": 20.0,
    "url": 20.0,
    "domain": 10.0,
    "ip_infrastructure": 10.0,
    "social_engineering": 10.0,
}

RISK_LEVELS = (
    (81, "critical"),
    (61, "high"),
    (41, "elevated"),
    (21, "medium"),
    (0, "low"),
)


@dataclass(slots=True)
class RiskEvidence:
    category: str
    severity: str = "medium"
    contribution: float | None = None
    title: str = ""
    reason: str = ""
    evidence: str | None = None


@dataclass(slots=True)
class RiskResult:
    risk_score: int
    risk_level: str
    confidence: float
    reasons: list[str] = field(default_factory=list)
    category_scores: dict[str, float] = field(default_factory=dict)
    evidence_count: int = 0


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, float(value)))


def _level(score: float) -> str:
    for minimum, name in RISK_LEVELS:
        if score >= minimum:
            return name
    return "low"


def _severity_multiplier(severity: str) -> float:
    return {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}.get(severity.lower(), 0.5)


def _normalized_weights(weights: dict[str, float] | None) -> dict[str, float]:
    merged = DEFAULT_WEIGHTS.copy()
    if weights:
        for key, value in weights.items():
            if key in merged:
                try:
                    merged[key] = max(0.0, float(value))
                except (TypeError, ValueError):
                    raise ValueError(f"Invalid risk weight for {key}")
    total = sum(merged.values())
    if total <= 0:
        raise ValueError("Risk weights must have a positive total")
    # Normalize to the 100-point scale while preserving relative weights.
    return {key: value * 100.0 / total for key, value in merged.items()}


def calculate_confidence(
    *,
    evidence: Iterable[RiskEvidence],
    ai_confidence: float | None = None,
    module_availability: dict[str, bool] | None = None,
) -> float:
    """Estimate evidence strength separately from danger/risk."""
    items = list(evidence)
    availability = module_availability or {}
    available = sum(1 for value in availability.values() if value)
    total_modules = len(availability)
    coverage = (available / total_modules) if total_modules else 1.0
    evidence_strength = min(1.0, len(items) / 8.0)
    ai = 0.0 if ai_confidence is None else _clamp(float(ai_confidence), 0, 1)
    # Confidence is evidence quality/coverage, not risk severity.
    confidence = 0.15 + 0.45 * coverage + 0.25 * evidence_strength + 0.15 * ai
    return round(_clamp(confidence, 0, 1), 3)


def calculate_risk(
    evidence: Iterable[RiskEvidence],
    *,
    weights: dict[str, float] | None = None,
    ai_confidence: float | None = None,
    module_availability: dict[str, bool] | None = None,
) -> RiskResult:
    """Calculate an explainable 0-100 risk score without double-counting categories.

    Each category contributes at most its configured weight. Within a category,
    multiple observations combine up to that category cap. This prevents the
    same underlying signal from inflating the total score repeatedly.
    """
    evidence = list(evidence)
    normalized = _normalized_weights(weights)
    grouped: dict[str, list[RiskEvidence]] = {key: [] for key in normalized}
    for item in evidence:
        category = item.category
        if category in grouped:
            grouped[category].append(item)

    category_scores: dict[str, float] = {}
    reasons: list[str] = []
    seen_reasons: set[str] = set()

    for category, category_items in grouped.items():
        cap = normalized[category]
        raw = 0.0
        for item in category_items:
            contribution = item.contribution
            if contribution is None:
                contribution = _severity_multiplier(item.severity) * cap
            raw += max(0.0, float(contribution))
            reason = item.reason or item.title
            if reason and reason not in seen_reasons:
                reasons.append(reason)
                seen_reasons.add(reason)
        category_scores[category] = round(min(cap, raw), 2)

    score = int(round(_clamp(sum(category_scores.values()), 0, 100)))
    confidence = calculate_confidence(
        evidence=evidence,
        ai_confidence=ai_confidence,
        module_availability=module_availability,
    )
    return RiskResult(
        risk_score=score,
        risk_level=_level(score),
        confidence=confidence,
        reasons=reasons[:12],
        category_scores=category_scores,
        evidence_count=len(evidence),
    )
