# SIH26106 — Phase 10: Investigation Orchestration

Phase 10 adds the main orchestration layer. It coordinates the already-built Phase 5–9 services in this order:

```text
stored email
  -> parser
  -> header forensics/authentication
  -> URL/domain/IP intelligence
  -> AI/NLP
  -> risk engine
  -> analysis + indicator persistence
```

## Endpoint

```http
POST /api/v1/analysis
Authorization: Bearer <JWT>
Content-Type: application/json

{"email_id": 123}
```

Only `admin` and `analyst` roles can start an investigation.

## Design notes

- Processing is synchronous for the MVP, as allowed by the project specification.
- The service is structured as one orchestration function so a later worker/queue can call it without changing the forensic modules.
- URL analysis is passive: arbitrary URLs from the email are never fetched.
- AI/external intelligence failures do not fabricate results; the pipeline continues with available evidence.
- A database transaction is used for the final persistence. Errors roll back the investigation transaction.
- The result keeps module availability separate from risk, supporting the Phase 9 confidence model.

## Run

Use the same environment and dependencies from the preceding phase:

```bash
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --reload
```

Swagger:

```text
http://localhost:8000/docs
```

## Test

```bash
pytest -q tests/test_phase10_investigation.py
```

## Known limitation

Phase 10 intentionally does not implement the later graph/report/history API layers. Those remain separate phases in the development plan.
