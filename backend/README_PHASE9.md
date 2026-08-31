# SIH26106 — Phase 9: Explainable Risk Scoring Engine

Phase 9 adds the configurable, explainable 0–100 risk scoring engine described in the SIH26106 development plan.

## Scope

- `app/services/risk_engine.py`
- `app/schemas/risk.py`
- `app/api/routes/risk.py`
- Phase 8 remains the base; Phase 10+ is intentionally not implemented.

## Scoring model

Default category weights:

| Category | Weight |
|---|---:|
| AI/NLP | 30 |
| Authentication/Header | 20 |
| URL | 20 |
| Domain | 10 |
| IP/Infrastructure | 10 |
| Social Engineering | 10 |

Risk levels:

- 0–20: LOW
- 21–40: MEDIUM
- 41–60: ELEVATED
- 61–80: HIGH
- 81–100: CRITICAL

Weights are normalized to a 100-point total. Each category is capped at its configured weight, preventing repeated observations from double-counting the same evidence category.

## Confidence

Confidence is deliberately separate from risk. It considers evidence coverage, number of observations, and optional AI confidence. A dangerous email with weak evidence can therefore have high risk but lower confidence.

## API

`POST /api/v1/risk/calculate`

JWT roles: `admin`, `analyst`.

Example request:

```json
{
  "evidence": [
    {
      "category": "ai_nlp",
      "severity": "critical",
      "contribution": 30,
      "reason": "High phishing probability"
    },
    {
      "category": "authentication_header",
      "severity": "high",
      "contribution": 15,
      "reason": "DMARC authentication failed"
    },
    {
      "category": "url",
      "severity": "high",
      "contribution": 15,
      "reason": "Suspicious credential URL"
    }
  ],
  "ai_confidence": 0.94,
  "module_availability": {
    "ai_nlp": true,
    "authentication_header": true,
    "url": true,
    "domain": false,
    "ip_infrastructure": true,
    "social_engineering": true
  }
}
```

The endpoint returns the score, level, confidence, category breakdown, and human-readable reasons.

## Test

From the project root:

```bash
pytest -q tests/test_phase9_risk.py
```

Phase 10 orchestration is intentionally not included.
