import os
os.environ["CORS_ORIGINS"] = "http://localhost:3000,http://localhost:5173"

from app.config import Settings


def test_cors_origins_are_parsed():
    settings = Settings()
    assert "http://localhost:3000" in settings.cors_origins
    assert "http://localhost:5173" in settings.cors_origins


def test_frontend_contract_files_exist():
    from pathlib import Path
    root = Path(__file__).parents[1]
    assert (root / "frontend-contract" / "api.ts").exists()
    assert (root / "frontend-contract" / ".env.example").exists()
