from __future__ import annotations

from pydantic import BaseModel, Field


class RawEmailCreate(BaseModel):
    raw_email: str = Field(min_length=1, max_length=10 * 1024 * 1024)


class EmailUploadResponse(BaseModel):
    email_id: int
    filename: str
    size_bytes: int
    status: str


class RawEmailResponse(EmailUploadResponse):
    pass
