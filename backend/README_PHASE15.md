# SIH26106 — Phase 15: Frontend Integration

Phase 15 completes the backend/frontend integration contract. It does not add a separate React application; it makes the FastAPI backend ready for a React dashboard and provides a small TypeScript API client starter.

## Implemented

- Configurable CORS using `CORS_ORIGINS`.
- Credentials enabled for JWT-bearing browser requests.
- Explicit HTTP methods and headers; no production wildcard CORS.
- Stable `/api/v1/*` REST namespace.
- OpenAPI at `/openapi.json` and Swagger UI at `/docs`.
- ReDoc at `/redoc`.
- `frontend-contract/api.ts` starter client for login, upload, analysis, investigations and graph.
- `frontend-contract/.env.example` with `VITE_API_BASE_URL`.

## Backend configuration

```env
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
```

For production, replace these with the exact deployed frontend origins. Do not use `*` when credentials are enabled.

## React usage

Copy `frontend-contract/api.ts` into the React project and configure:

```env
VITE_API_BASE_URL=http://localhost:8000
```

Store the access token using the frontend application's preferred secure session strategy. Send it as:

```text
Authorization: Bearer <access_token>
```

## Main dashboard flow

1. Login: `POST /api/v1/auth/login`
2. Upload `.eml`: `POST /api/v1/emails/upload`
3. Start analysis: `POST /api/v1/analysis`
4. Poll status: `GET /api/v1/analysis/{id}`
5. Load investigation: `GET /api/v1/investigations/{id}`
6. Load graph: `GET /api/v1/investigations/{id}/graph`
7. Export report: `GET /api/v1/investigations/{id}/report/html` or `/pdf`

## Contract principle

The frontend should depend on the versioned API paths and response schemas, not internal service/database modules. Internal implementation can evolve while `/api/v1` remains stable.

## Run

```bash
uvicorn app.main:app --reload
```

Open `http://localhost:8000/docs` and test the API with a JWT obtained from login.
