from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from app.config import settings

password_hash = PasswordHash((Argon2Hasher(),))


def validate_secret_key() -> None:
    if len(settings.secret_key) < 32 and settings.app_env != "test":
        raise RuntimeError("SECRET_KEY must be at least 32 characters in non-test environments")


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    try:
        return password_hash.verify(password, hashed_password)
    except Exception:
        return False


def create_access_token(subject: str, role: str) -> str:
    validate_secret_key()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": subject, "role": role, "iat": now, "exp": expires, "type": "access"}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    validate_secret_key()
    return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
