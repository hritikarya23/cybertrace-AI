# SIH26106 — Phase 2: PostgreSQL + SQLAlchemy + Alembic + Models

This phase implements the database layer requested in the development order: PostgreSQL configuration, SQLAlchemy 2.x async session management, the complete Phase-2 ORM model set, and an Alembic initial migration.

## Included

- `app/database/database.py` — async engine, `Base`, session factory, FastAPI `get_db` dependency.
- `app/database/models.py` — ORM models for users, emails, headers, routing hops, URLs, domains, IPs, analyses, indicators, authentication results, graph nodes/edges, and reports.
- `app/database/migrations/env.py` — async Alembic environment.
- `app/database/migrations/versions/0001_initial_schema.py` — initial schema migration.
- `alembic.ini` — Alembic configuration.

## Run

From the project root, install:

```bash
pip install -r requirements-phase2.txt
```

Set the database URL through the Phase-1 configuration/environment in the final app. The migration template currently defaults to:

```text
postgresql+asyncpg://postgres:postgres@db:5432/email_forensics
```

Then:

```bash
alembic upgrade head
```

## Important integration note

The complete application should have one authoritative `DATABASE_URL` in `app/config.py` (Phase 1). Before integrating this phase, replace the fallback constant in `database.py` with the Phase-1 settings object, for example by constructing the engine from `settings.database_url`.

## Design notes

- Foreign keys use `ON DELETE CASCADE` for investigation-owned records.
- Common lookup paths are indexed.
- `authentication_results.email_id` is one-to-one.
- Graph nodes are unique per analysis/type/value to avoid duplicate entities.
- External intelligence fields are nullable; unavailable data remains `NULL` rather than fabricated.
- Raw email content is stored only where the Phase-2 schema requires it; later APIs must avoid exposing it unnecessarily.
