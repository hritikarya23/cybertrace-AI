from __future__ import annotations

import re
import secrets
from pathlib import Path

from fastapi import UploadFile

from app.config import settings

_SAFE_EXTENSIONS = {".eml"}
_SAFE_NAME = re.compile(r"[^a-zA-Z0-9._-]")


class EmailStorageError(Exception):
    """Raised when an email cannot be safely stored."""


class EmailTooLargeError(EmailStorageError):
    """Raised when an email exceeds the configured size limit."""


def storage_root() -> Path:
    root = Path(settings.upload_storage_path).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def validate_eml_filename(filename: str | None) -> str:
    if not filename:
        raise EmailStorageError("A filename is required")
    original = Path(filename).name
    if Path(original).suffix.lower() not in _SAFE_EXTENSIONS:
        raise EmailStorageError("Only .eml files are accepted")
    return original


def safe_storage_name() -> str:
    return f"{secrets.token_hex(16)}.eml"


def _ensure_size(current: int, incoming: int) -> None:
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    if current + incoming > max_bytes:
        raise EmailTooLargeError(
            f"Email exceeds maximum size of {settings.max_upload_size_mb} MB"
        )


async def save_upload(file: UploadFile) -> tuple[str, int]:
    """Stream an uploaded .eml file to private storage without trusting its name."""
    validate_eml_filename(file.filename)
    destination = storage_root() / safe_storage_name()
    total = 0
    try:
        with destination.open("xb") as output:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                _ensure_size(total, len(chunk))
                output.write(chunk)
                total += len(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await file.close()
    return destination.name, total


def save_raw(raw_email: str) -> tuple[str, int]:
    """Store raw email text under a cryptographically random filename."""
    data = raw_email.encode("utf-8")
    _ensure_size(0, len(data))
    destination = storage_root() / safe_storage_name()
    try:
        with destination.open("xb") as output:
            output.write(data)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return destination.name, len(data)


def absolute_storage_path(filename: str) -> Path:
    """Resolve a stored filename and prevent path traversal."""
    root = storage_root()
    candidate = (root / Path(filename).name).resolve()
    if candidate.parent != root or candidate.suffix.lower() != ".eml":
        raise EmailStorageError("Invalid stored email path")
    return candidate
