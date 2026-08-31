from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, ConfigDict


class AttachmentMetadataResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    filename: str | None
    content_type: str
    size: int
    sha256: str


class URLMetadataResponse(BaseModel):
    url: str
    normalized_url: str
    domain: str | None
    scheme: str | None
    port: int | None
    path: str | None


class ParsedEmailResponse(BaseModel):
    email_id: int
    sender: str | None
    recipients: list[str]
    cc: list[str]
    bcc: list[str]
    reply_to: str | None
    return_path: str | None
    subject: str | None
    date: datetime | None
    message_id: str | None
    body_text: str
    body_html: str
    headers: list[dict[str, str]]
    received_headers: list[str]
    authentication_results: list[str]
    dkim_signatures: list[str]
    arc_headers: list[dict[str, str]]
    content_types: list[str]
    urls: list[URLMetadataResponse]
    ip_addresses: list[str]
    attachments: list[AttachmentMetadataResponse]
