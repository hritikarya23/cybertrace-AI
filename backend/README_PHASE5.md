# SIH26106 — Phase 5: Email Parser

Phase 5 adds the real email parsing layer to the Phase-4 backend. The implementation follows the project specification: headers, sender/recipient metadata, subject/date/message-id, text/HTML body, URLs, IP addresses, attachment metadata, and relevant raw header groups are extracted without executing attachments or remote content.

## Endpoint

`POST /api/v1/emails/{email_id}/parse`

Requires JWT and `admin` or `analyst` role. The endpoint only parses an email owned by the authenticated user.

## What is extracted

- From / To / Cc / Bcc
- Reply-To / Return-Path
- Subject / Date / Message-ID
- All raw headers
- Received headers
- Authentication-Results headers (extracted only; verification is Phase 6)
- DKIM-Signature headers (extracted only; cryptographic verification is Phase 6)
- ARC headers
- Content types
- Plain-text and HTML bodies
- URLs from text and HTML `href`/`src`
- IP addresses from headers
- Attachment filename, MIME type, byte size and SHA-256 hash

Attachments are never executed and their contents are not returned by the API.

## Run

```bash
cp .env.example .env
pip install -r requirements-phase3.txt
alembic upgrade head
uvicorn app.main:app --reload
```

Open `http://localhost:8000/docs`.

## Test

```bash
pytest -q
```

## Important limitation

Phase 5 only extracts data. SPF/DKIM/DMARC interpretation, Received-hop forensics, URL/domain/IP threat scoring, AI, and risk scoring belong to later phases.
