from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "AI Email Forensic Intelligence Platform")
    app_env: str = os.getenv("APP_ENV", "development")
    debug: bool = _bool("DEBUG", False)
    database_url: str = os.getenv(
        "DATABASE_URL", "postgresql+asyncpg://postgres:postgres@db:5432/email_forensics"
    )
    secret_key: str = os.getenv("SECRET_KEY", "")
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    max_upload_size_mb: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))
    upload_storage_path: str = os.getenv("UPLOAD_STORAGE_PATH", "./uploads")
    report_storage_path: str = os.getenv("REPORT_STORAGE_PATH", "./reports")
    cors_origins: tuple[str, ...] = tuple(
        origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173").split(",") if origin.strip()
    )


settings = Settings()
