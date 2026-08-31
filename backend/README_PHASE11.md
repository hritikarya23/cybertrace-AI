# SIH26106 — Phase 11: Database Persistence

Phase 11 focuses on safe, atomic persistence of investigation results in PostgreSQL using SQLAlchemy 2.x.

## Implemented
- `app/services/persistence_service.py`
- Explicit transaction boundary helper with rollback on SQLAlchemy failure
- Deterministic replacement of parser-derived email rows
- Atomic final analysis + indicator persistence
- Score/confidence bounds enforced before persistence
- Investigation service now delegates final persistence to the persistence service
- Existing Phase 2 PostgreSQL schema and Alembic migration retained

## Transaction principle
The investigation service should not expose partially persisted forensic results as a completed investigation. Final analysis fields and indicators are written in the same transaction and committed only after all required work succeeds.

## Run
```bash
pip install -r requirements-phase10.txt
alembic upgrade head
uvicorn app.main:app --reload
```

## Test
```bash
PYTHONPATH=. pytest -q tests/test_phase11_persistence.py
```

## Scope
Phase 11 only adds/strengthens persistence. Investigation APIs, graph generation and report generation are not new Phase 11 features.
