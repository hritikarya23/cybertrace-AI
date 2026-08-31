# SIH26106 — AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

Backend for a Smart India Hackathon project: analysts upload a raw/.eml
email and the system investigates it — header forensics, SPF/DKIM/DMARC,
URL & domain analysis, IP intelligence & geolocation, AI/NLP phishing
detection — and returns an explainable risk score, forensic report, and
relationship graph.

Modular monolith, built with FastAPI + PostgreSQL + SQLAlchemy 2.x.

## Build status

Being built in 15 phases. Completed so far:

- [x] **Phase 1 — Project foundation** (this phase)
- [ ] Phase 2 — Database layer (PostgreSQL, SQLAlchemy models, Alembic)
- [ ] Phase 3 — Authentication (JWT, password hashing, user model)
- [ ] Phase 4 — Email upload & parsing (.eml, `email` stdlib)
- [ ] Phase 5 — Header forensics (Received chain reconstruction, Reply-To/Return-Path)
- [ ] Phase 6 — SPF / DKIM / DMARC analysis
- [ ] Phase 7 — URL extraction & suspicious URL analysis
- [ ] Phase 8 — Domain analysis & look-alike/impersonation detection
- [ ] Phase 9 — IP extraction & IP intelligence
- [ ] Phase 10 — Geolocation & hosting/ISP/ASN enrichment
- [ ] Phase 11 — NLP / social-engineering & AI phishing detector
- [ ] Phase 12 — Risk engine (explainable scoring & indicators)
- [ ] Phase 13 — Relationship graph construction
- [ ] Phase 14 — Investigation persistence & history APIs
- [ ] Phase 15 — Forensic report generation (downloadable)

## Requirements

- Python 3.11+
- (from Phase 2 onward) PostgreSQL 14+, or Docker

## Local setup (Phase 1)

```bash
cd backend

# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env             # defaults work out of the box for Phase 1

# 4. Run the API
uvicorn app.main:app --reload
```

The API is now available at:

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- OpenAPI schema: http://localhost:8000/openapi.json
- Health check: http://localhost:8000/api/v1/health

## Running tests

```bash
pytest -v
```

## Project structure

```
backend/
├── app/
│   ├── main.py              # FastAPI app factory + entrypoint
│   ├── config.py            # Environment-driven settings (pydantic-settings)
│   ├── api/
│   │   ├── router.py        # Aggregates all versioned route modules
│   │   ├── dependencies.py  # Shared FastAPI dependencies (added Phase 2/3)
│   │   └── routes/
│   │       └── health.py    # GET /api/v1/health
│   ├── core/
│   │   ├── security.py      # JWT + password hashing (stub; built out Phase 3)
│   │   ├── logging.py       # Centralized logging setup
│   │   └── exceptions.py    # Exception hierarchy + JSON error envelope
│   ├── database/            # SQLAlchemy engine/session/models (Phase 2)
│   ├── schemas/             # Pydantic request/response models (from Phase 2 on)
│   ├── services/            # Business logic — parsers, analyzers, risk engine, etc.
│   └── utils/                # Small stateless helpers (URL/IP/text utils)
├── tests/
├── uploads/                 # Uploaded .eml files land here (Phase 4+)
├── reports/                 # Generated forensic reports land here (Phase 15)
├── requirements.txt
├── .env.example
└── README.md
```

## Design notes

- **Modular monolith, not microservices.** Every analysis stage (header,
  auth, URL, domain, IP, geolocation, AI/NLP, risk, graph) lives in its own
  service module under `app/services/`, but they run in a single process
  and are composed by an investigation orchestrator (built in Phase 14).
  This keeps the system simple to run, test, and demo within a hackathon
  timeline while still being cleanly separated internally.
- **No fabricated threat intelligence.** Where a phase depends on an
  external API (IP intel, geolocation, ASN/hosting data) that may not have
  credentials configured, the corresponding service exposes a clear
  interface with a safe, explicitly-labeled fallback/mock mode rather than
  inventing data. Responses will indicate when a result came from a mock
  provider so the frontend can flag it as non-authoritative.
- **Consistent error envelope.** All errors (validation, not-found, auth,
  external-service failures, unexpected exceptions) go through
  `app/core/exceptions.py` and return the same JSON shape:
  `{"success": false, "error": {"code", "message", "details"}}`.


# SIH26106 Complete Backend — Phases 1 to 16

This repository merges the Phase 1 backend supplied by the user with the generated Phase 2–16 artifacts.

## Development sequence
1. Project setup
2. PostgreSQL / SQLAlchemy / Alembic / models
3. Authentication / JWT / roles
4. Email upload / raw email / secure storage
5. Email parsing
6. Header forensics / SPF / DKIM / DMARC / Received routing
7. URL / domain / IP services
8. AI / NLP service
9. Risk engine
10. Investigation orchestration
11. Persistence
12. Investigation APIs
13. Graph
14. Reports
15. Frontend integration
16. Tests / Docker / documentation / security review

## Run locally
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
alembic upgrade head
uvicorn app.main:app --reload
```

## Run with Docker
```bash
docker compose up --build
docker compose exec backend alembic upgrade head
```

Open:
`http://localhost:8000/docs`

## Important
This merge preserves the latest file encountered for overlapping paths while retaining Phase 1 as the initial project scaffold. Because the generated phase packages were developed independently, run the full integration test suite and inspect any overlapping API/model files before production use.
