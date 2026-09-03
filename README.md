# cybertrace-AI

## Run the complete application with Docker

Docker Desktop is the only prerequisite. The database, API, frontend, and database migrations start with one command:

```powershell
docker compose up --build
```

Open the frontend at http://localhost:5173, the API documentation at http://localhost:8000/docs, and PostgreSQL from the host on `localhost:5401`. Alembic migrations run automatically before the API starts. In this development configuration, frontend and backend source changes reload automatically.

Stop services with `docker compose down`. To also remove the database volume and start with an empty database, use `docker compose down -v`.

### Production-like containers

Set strong secrets in your PowerShell session, then run:

```powershell
$env:POSTGRES_PASSWORD = "replace-with-a-strong-database-password"
$env:SECRET_KEY = "replace-with-a-random-secret-at-least-32-characters"
docker compose -f docker-compose.prod.yml up --build -d
```

The production frontend is available at http://localhost:8080. The backend remains at http://localhost:8000 and PostgreSQL at `localhost:5401` for local operational access. Do not expose the database port publicly when deploying to a server.
