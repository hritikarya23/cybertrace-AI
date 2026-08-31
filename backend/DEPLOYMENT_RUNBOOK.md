# Deployment Runbook
1. Copy `.env.example` to `.env`.
2. Set a unique production SECRET_KEY.
3. Set DEBUG=false and exact CORS origins.
4. Disable MOCK_EXTERNAL_SERVICES.
5. Configure approved external providers.
6. Start PostgreSQL and backend.
7. Run `alembic upgrade head`.
8. Check `/api/v1/health`.
9. Test login with a non-production account.
10. Upload a harmless synthetic `.eml`.
11. Run analysis and verify investigation detail.
12. Verify graph and HTML/PDF reports.
13. Confirm logs contain no secrets/full email bodies.
