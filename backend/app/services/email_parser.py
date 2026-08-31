from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit

URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"']+")
IP_RE = re.compile(r"(?<![\w:.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){2,7})(?![\w:.])", re.I)


@dataclass(slots=True)
class AttachmentMetadata:
    filename: str | None
    content_type: str
    size: int
    sha256: str


@dataclass(slots=True)
class URLMetadata:
    url: str
    normalized_url: str
    domain: str | None
    scheme: str | None
    port: int | None
    path: str | None


@dataclass(slots=True)
class ParsedEmail:
    sender: str | None = None
    recipients: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    bcc: list[str] = field(default_factory=list)
    reply_to: str | None = None
    return_path: str | None = None
    subject: str | None = None
    date: datetime | None = None
    message_id: str | None = None
    body_text: str = ""
    body_html: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    received_headers: list[str] = field(default_factory=list)
    authentication_results: list[str] = field(default_factory=list)
    dkim_signatures: list[str] = field(default_factory=list)
    arc_headers: list[tuple[str, str]] = field(default_factory=list)
    content_types: list[str] = field(default_factory=list)
    urls: list[URLMetadata] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    attachments: list[AttachmentMetadata] = field(default_factory=list)


class _HTMLTextExtractor(HTMLParser):
    """Extract visible-ish text and href/src attributes without executing HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data.strip())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name.lower() in {"href", "src"} and value:
                self.links.append(value)


def _header_values(message: Message, name: str) -> list[str]:
    return [str(value) for value in message.get_all(name, [])]


def _first_header(message: Message, name: str) -> str | None:
    values = _header_values(message, name)
    return values[0] if values else None


def _addresses(value: str | None) -> list[str]:
    if not value:
        return []
    return [address for _, address in getaddresses([value]) if address]


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


def _normalize_url(value: str) -> URLMetadata | None:
    value = value.strip().strip("<>[](){}.,;:'\"\r\n\t")
    if not re.match(r"(?i)^(https?|ftp)://", value):
        return None
    try:
        parts = urlsplit(value)
        if not parts.hostname:
            return None
        hostname = parts.hostname.rstrip(".").lower()
        scheme = parts.scheme.lower()
        try:
            port = parts.port
        except ValueError:
            port = None
        normalized = urlunsplit((scheme, parts.netloc, parts.path or "", parts.query, parts.fragment))
        return URLMetadata(
            url=value,
            normalized_url=normalized,
            domain=hostname,
            scheme=scheme,
            port=port,
            path=parts.path or None,
        )
    except ValueError:
        return None


def _extract_urls(text: str, html: str) -> list[URLMetadata]:
    candidates = URL_RE.findall(text)
    if html:
        parser = _HTMLTextExtractor()
        try:
            parser.feed(html)
            candidates.extend(parser.links)
        except Exception:
            pass
        candidates.extend(URL_RE.findall(html))

    seen: set[str] = set()
    result: list[URLMetadata] = []
    for candidate in candidates:
        parsed = _normalize_url(candidate)
        if parsed and parsed.normalized_url not in seen:
            seen.add(parsed.normalized_url)
            result.append(parsed)
    return result


def _valid_ips(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        canonical = str(address)
        if canonical not in seen:
            seen.add(canonical)
            result.append(canonical)
    return result


def _body_parts(message: Message) -> tuple[str, str]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        content_type = part.get_content_type().lower()
        if disposition == "attachment":
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError):
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            content = payload.decode(charset, errors="replace")
        if not isinstance(content, str):
            continue
        if content_type == "text/plain":
            text_parts.append(content)
        elif content_type == "text/html":
            html_parts.append(content)
    return "\n\n".join(text_parts), "\n\n".join(html_parts)


def _attachment_metadata(message: Message) -> list[AttachmentMetadata]:
    result: list[AttachmentMetadata] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() != "attachment" and not part.get_filename():
            continue
        payload = part.get_payload(decode=True) or b""
        result.append(
            AttachmentMetadata(
                filename=part.get_filename(),
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    return result


def parse_email(raw_email: bytes | str) -> ParsedEmail:
    """Parse an RFC 5322 email without executing attachments or remote content."""
    raw = raw_email.encode("utf-8", errors="replace") if isinstance(raw_email, str) else raw_email
    message = BytesParser(policy=policy.default).parsebytes(raw)

    body_text, body_html = _body_parts(message)
    all_header_values = [(name, str(value)) for name, value in message.raw_items()]
    received = _header_values(message, "Received")
    auth = _header_values(message, "Authentication-Results")
    dkim = _header_values(message, "DKIM-Signature")
    arc = [(name, value) for name, value in all_header_values if name.lower().startswith("arc-")]

    # IPs are extracted from headers, not arbitrary attachment bytes.
    header_blob = "\n".join(value for _, value in all_header_values)
    ips = _valid_ips(IP_RE.findall(header_blob))

    sender = _addresses(_first_header(message, "From"))
    reply_to = _addresses(_first_header(message, "Reply-To"))

    return ParsedEmail(
        sender=sender[0] if sender else _first_header(message, "From"),
        recipients=_addresses(_first_header(message, "To")),
        cc=_addresses(_first_header(message, "Cc")),
        bcc=_addresses(_first_header(message, "Bcc")),
        reply_to=reply_to[0] if reply_to else _first_header(message, "Reply-To"),
        return_path=_first_header(message, "Return-Path"),
        subject=_first_header(message, "Subject"),
        date=_parse_date(_first_header(message, "Date")),
        message_id=_first_header(message, "Message-ID"),
        body_text=body_text,
        body_html=body_html,
        headers=all_header_values,
        received_headers=received,
        authentication_results=auth,
        dkim_signatures=dkim,
        arc_headers=arc,
        content_types=sorted({part.get_content_type() for part in message.walk()}),
        urls=_extract_urls(body_text, body_html),
        ip_addresses=ips,
        attachments=_attachment_metadata(message),
    )


def parse_email_file(path: str | Path) -> ParsedEmail:
    """Read a private stored .eml file and parse it as bytes."""
    return parse_email(Path(path).read_bytes())
