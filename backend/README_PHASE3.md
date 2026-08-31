# SIH26106 — Phase 3: Authentication, JWT & Roles

Phase 3 implements the authentication layer specified by the SIH26106 backend plan: JWT authentication, secure password hashing, protected endpoints, and `admin` / `analyst` / `viewer` roles.

## Included

- Argon2 password hashing via `pwdlib`
- JWT access tokens via PyJWT
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `GET /api/v1/auth/me`
- `get_current_user` dependency
- `require_roles()` RBAC dependency
- inactive-user protection
- case-normalized email lookup
- admin self-registration prevention
- environment-based secret and token expiry
- tests for password and JWT behavior

## Role policy

- `admin`: intended for all operations
- `analyst`: upload/analyze/view/export
- `viewer`: view only

Public registration only permits `analyst` or `viewer`; administrator accounts must be provisioned by a trusted/admin process rather than by an open registration request.

## Run

```bash
cp .env.example .env
pip install -r requirements-phase3.txt
uvicorn app.main:app --reload
```

For PostgreSQL, set `DATABASE_URL` in `.env` and run the Phase 2 Alembic migration first:

```bash
alembic upgrade head
```

Docs: `http://localhost:8000/docs`

## Example

Register:

```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "analyst@example.com",
  "password": "StrongPassword123!",
  "full_name": "Security Analyst",
  "role": "analyst"
}
```

Login:

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "analyst@example.com",
  "password": "StrongPassword123!"
}
```

Use the returned `access_token` as:

```text
Authorization: Bearer <access_token>
```

## Security notes

- Passwords are never stored in plaintext.
- JWT secrets are never hardcoded in application logic.
- Tokens expire according to `ACCESS_TOKEN_EXPIRE_MINUTES`.
- Invalid, expired, malformed, inactive-user, and unauthorized requests are rejected.
- Do not use weak secrets in production.
- This phase does not implement rate limiting; that belongs to the broader security layer planned for the complete backend.
