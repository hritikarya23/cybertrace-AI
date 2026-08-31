# SIH26106 — Phase 6: Header Forensics

Phase 6 adds passive email header forensics to the Phase 5 backend.

## Scope

- From vs Reply-To mismatch detection
- From vs Return-Path mismatch detection
- Message-ID domain consistency check
- Authentication-Results parsing for SPF, DKIM and DMARC
- DKIM-Signature `d=` and `s=` extraction
- Multiple `Received` header parsing
- Routing hop normalization
- Private/public IP classification
- Conservative earliest reliable sending-node heuristic
- PostgreSQL persistence in `authentication_results` and `received_hops`

## Endpoint

`POST /api/v1/emails/{email_id}/forensics`

Requires an authenticated `admin` or `analyst` and an email owned by that user.

## Important forensic limitations

This phase is passive. It does not perform DNS lookups, visit URLs, or cryptographically verify DKIM. Authentication values are parsed from the message's `Authentication-Results` headers; missing values remain `unknown`, not `fail`.

The earliest reliable node is only an estimated infrastructure origin. It is **not** proof of an attacker's personal IP, identity, or physical location.

## Run

```bash
pip install -r requirements-phase3.txt
alembic upgrade head
uvicorn app.main:app --reload
```

Open `/docs` and call the endpoint after uploading an `.eml` through Phase 4.
