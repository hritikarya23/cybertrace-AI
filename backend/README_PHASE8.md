# SIH26106 — Phase 8: AI / NLP Service

Phase 8 adds the AI/NLP abstraction required by the project specification. It intentionally does not implement Phase 9 risk scoring or later orchestration.

## Endpoint

`POST /api/v1/emails/{email_id}/ai`

Requires JWT and `admin` or `analyst` role.

## Supported modes

1. **Mock mode** — `MOCK_EXTERNAL_SERVICES=true`. Deterministic demo output is returned and explicitly marked `mock: true`.
2. **Local model adapter** — configure `AI_LOCAL_MODEL_PATH=module:function`. The function receives `(subject, body)` and must return a dictionary matching the normalized AI result fields.
3. **External AI service** — configure `AI_SERVICE_URL` and optionally `AI_SERVICE_API_KEY`.

If no real AI service is configured, the service returns `status: unavailable`; it does not fabricate AI results.

## Example normalized result

```json
{
  "classification": "phishing",
  "confidence": 0.94,
  "phishing_probability": 0.94,
  "indicators": [
    {"type": "urgency", "description": "Urgency-oriented language detected"}
  ],
  "status": "completed",
  "source": "external",
  "mock": false,
  "reason": null
}
```

## External service contract

The backend sends:

```json
{"subject": "...", "body": "..."}
```

The service should return a JSON object containing `classification`, `confidence`, `phishing_probability`, and optionally `indicators`.

## Safety

The service only sends the email subject/body to the configured AI endpoint. It does not execute attachments or visit URLs. Timeouts and HTTP failures are converted into an unavailable result so the wider forensic workflow can continue.
