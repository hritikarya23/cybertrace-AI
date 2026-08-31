# SIH26106 — Phase 12: Investigation APIs

Phase 12 implements the investigation-facing REST APIs only. It does not implement graph generation or report generation.

## Endpoints

- `GET /api/v1/investigations`
  - `page`, `page_size`
  - `classification`
  - `risk_level`
  - `date_from`, `date_to`
  - `search` (sender, subject, message-id)
- `GET /api/v1/investigations/{analysis_id}`
- `GET /api/v1/investigations/{analysis_id}/indicators`
  - optional `severity` and `category`

All endpoints require JWT authentication and only return investigations belonging to the authenticated user.

## Response coverage

The detail endpoint exposes the frontend-friendly sections specified for the investigation dashboard: analysis/threat, email metadata, authentication, headers, routing, URLs, domains, IPs, geolocation status, indicators, risk, and persisted graph data.

## Validation

Use FastAPI OpenAPI docs at `/docs` after installing dependencies and starting the backend.

Phase 13 is intentionally not included.
