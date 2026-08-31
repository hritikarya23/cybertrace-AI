from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import require_roles
from app.database.database import get_db
from app.database.models import Email, User
from app.schemas.email import EmailUploadResponse, RawEmailCreate, RawEmailResponse
from app.schemas.parser import ParsedEmailResponse
from app.services.email_storage import (
    EmailStorageError,
    EmailTooLargeError,
    save_raw,
    save_upload,
)

router = APIRouter(prefix="/api/v1/emails", tags=["Emails"])


@router.post("/upload", response_model=EmailUploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_email(
    file: UploadFile = File(...),
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
) -> EmailUploadResponse:
    """Securely store a synthetic or real .eml file for later forensic analysis."""
    try:
        stored_name, size = await save_upload(file)
    except EmailTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except EmailStorageError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    email = Email(user_id=current_user.id, raw_email_path=stored_name)
    db.add(email)
    try:
        await db.commit()
        await db.refresh(email)
    except Exception:
        await db.rollback()
        from app.services.email_storage import absolute_storage_path
        absolute_storage_path(stored_name).unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="Unable to persist uploaded email")

    return EmailUploadResponse(
        email_id=email.id,
        filename=stored_name,
        size_bytes=size,
        status="uploaded",
    )


@router.post("/raw", response_model=RawEmailResponse, status_code=status.HTTP_201_CREATED)
async def submit_raw_email(
    payload: RawEmailCreate,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
) -> RawEmailResponse:
    """Store raw email content without exposing it through the public filesystem."""
    try:
        stored_name, size = save_raw(payload.raw_email)
    except EmailTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except EmailStorageError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    email = Email(user_id=current_user.id, raw_email_path=stored_name)
    db.add(email)
    try:
        await db.commit()
        await db.refresh(email)
    except Exception:
        await db.rollback()
        from app.services.email_storage import absolute_storage_path
        absolute_storage_path(stored_name).unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="Unable to persist raw email")

    return RawEmailResponse(
        email_id=email.id,
        filename=stored_name,
        size_bytes=size,
        status="uploaded",
    )

@router.post("/{email_id}/parse", response_model=ParsedEmailResponse)
async def parse_stored_email(
    email_id: int,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
) -> ParsedEmailResponse:
    """Parse a previously uploaded raw email and persist Phase-5 extracted data."""
    from sqlalchemy import delete, select
    from app.services.email_storage import absolute_storage_path
    from app.services.email_parser import parse_email_file
    from app.database.models import EmailHeader, URL, Domain, IPAddress

    result = await db.execute(select(Email).where(Email.id == email_id, Email.user_id == current_user.id))
    email = result.scalar_one_or_none()
    if email is None or not email.raw_email_path:
        raise HTTPException(status_code=404, detail="Email not found")

    try:
        path = absolute_storage_path(email.raw_email_path)
        parsed = parse_email_file(path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Stored email file is missing") from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Unable to parse stored email") from exc

    # Replace Phase-5 derived data so repeated parsing is deterministic.
    email.sender = parsed.sender
    email.recipient = ", ".join(parsed.recipients) or None
    email.reply_to = parsed.reply_to
    email.return_path = parsed.return_path
    email.subject = parsed.subject
    email.body_text = parsed.body_text
    email.body_html = parsed.body_html
    email.message_id = parsed.message_id
    email.received_at = parsed.date

    # Delete only Phase-5 derived rows; leave later-phase forensic rows untouched.
    await db.execute(delete(EmailHeader).where(EmailHeader.email_id == email.id))
    await db.execute(delete(URL).where(URL.email_id == email.id))
    await db.execute(delete(Domain).where(Domain.email_id == email.id))
    await db.execute(delete(IPAddress).where(IPAddress.email_id == email.id))

    for name, value in parsed.headers:
        email.headers.append(EmailHeader(header_name=name, header_value=value))
    for item in parsed.urls:
        email.urls.append(URL(
            url=item.url,
            normalized_url=item.normalized_url,
            domain=item.domain,
            scheme=item.scheme,
            port=item.port,
            path=item.path,
        ))
    for domain in sorted({u.domain for u in parsed.urls if u.domain}):
        email.domains.append(Domain(domain=domain))
    for ip in parsed.ip_addresses:
        address = __import__("ipaddress").ip_address(ip)
        email.ip_addresses.append(IPAddress(ip=ip, ip_version=address.version, is_private=address.is_private))

    await db.commit()

    return ParsedEmailResponse(
        email_id=email.id,
        sender=parsed.sender,
        recipients=parsed.recipients,
        cc=parsed.cc,
        bcc=parsed.bcc,
        reply_to=parsed.reply_to,
        return_path=parsed.return_path,
        subject=parsed.subject,
        date=parsed.date,
        message_id=parsed.message_id,
        body_text=parsed.body_text,
        body_html=parsed.body_html,
        headers=[{"name": n, "value": v} for n, v in parsed.headers],
        received_headers=parsed.received_headers,
        authentication_results=parsed.authentication_results,
        dkim_signatures=parsed.dkim_signatures,
        arc_headers=[{"name": n, "value": v} for n, v in parsed.arc_headers],
        content_types=parsed.content_types,
        urls=[{
            "url": u.url, "normalized_url": u.normalized_url, "domain": u.domain,
            "scheme": u.scheme, "port": u.port, "path": u.path,
        } for u in parsed.urls],
        ip_addresses=parsed.ip_addresses,
        attachments=[{
            "filename": a.filename, "content_type": a.content_type,
            "size": a.size, "sha256": a.sha256,
        } for a in parsed.attachments],
    )

@router.post("/{email_id}/forensics", response_model=__import__("app.schemas.forensics", fromlist=["HeaderForensicsResponse"]).HeaderForensicsResponse)
async def analyze_email_headers(
    email_id: int,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Run passive Phase-6 header forensics and persist authentication/routing findings."""
    from sqlalchemy import delete, select
    from app.database.models import AuthenticationResult, ReceivedHop
    from app.schemas.forensics import (
        AuthenticationForensicsResponse,
        HeaderForensicsResponse,
        ReceivedHopResponse,
    )
    from app.services.email_storage import absolute_storage_path
    from app.services.header_analyzer import analyze_headers

    result = await db.execute(select(Email).where(Email.id == email_id, Email.user_id == current_user.id))
    email = result.scalar_one_or_none()
    if email is None or not email.raw_email_path:
        raise HTTPException(status_code=404, detail="Email not found")

    try:
        raw = absolute_storage_path(email.raw_email_path).read_bytes()
        analysis = analyze_headers(raw)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Stored email file is missing") from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Unable to analyze email headers") from exc

    await db.execute(delete(ReceivedHop).where(ReceivedHop.email_id == email.id))
    await db.execute(delete(AuthenticationResult).where(AuthenticationResult.email_id == email.id))

    auth = AuthenticationResult(
        email_id=email.id,
        spf_result=analysis.authentication.spf_result,
        dkim_result=analysis.authentication.dkim_result,
        dmarc_result=analysis.authentication.dmarc_result,
        spf_domain=analysis.authentication.spf_domain,
        dkim_domain=analysis.authentication.dkim_domain,
        dmarc_policy=analysis.authentication.dmarc_policy,
        raw_authentication_header=analysis.authentication.raw_authentication_header,
    )
    db.add(auth)
    for hop in analysis.routing_hops:
        db.add(ReceivedHop(
            email_id=email.id,
            hop_order=hop.hop_order,
            raw_received_header=hop.raw_received_header,
            source_ip=hop.source_ip,
            source_hostname=hop.source_hostname,
            destination_hostname=hop.destination_hostname,
            timestamp=hop.timestamp,
            is_private_ip=hop.is_private_ip,
            is_public_ip=hop.is_public_ip,
            is_reliable=hop.is_reliable,
        ))
    await db.commit()

    def hop_response(hop):
        return ReceivedHopResponse(
            hop_order=hop.hop_order,
            raw_received_header=hop.raw_received_header,
            source_ip=hop.source_ip,
            source_hostname=hop.source_hostname,
            destination_hostname=hop.destination_hostname,
            timestamp=hop.timestamp,
            is_private_ip=hop.is_private_ip,
            is_public_ip=hop.is_public_ip,
            is_reliable=hop.is_reliable,
        )

    earliest = analysis.earliest_reliable_sending_node
    return HeaderForensicsResponse(
        email_id=email.id,
        from_address=analysis.from_address,
        reply_to=analysis.reply_to,
        return_path=analysis.return_path,
        message_id=analysis.message_id,
        from_reply_to_mismatch=analysis.from_reply_to_mismatch,
        from_return_path_mismatch=analysis.from_return_path_mismatch,
        message_id_domain=analysis.message_id_domain,
        from_domain=analysis.from_domain,
        message_id_domain_consistent=analysis.message_id_domain_consistent,
        authentication=AuthenticationForensicsResponse(
            spf_result=analysis.authentication.spf_result,
            dkim_result=analysis.authentication.dkim_result,
            dmarc_result=analysis.authentication.dmarc_result,
            spf_domain=analysis.authentication.spf_domain,
            dkim_domain=analysis.authentication.dkim_domain,
            dmarc_policy=analysis.authentication.dmarc_policy,
            raw_authentication_header=analysis.authentication.raw_authentication_header,
        ),
        routing_hops=[hop_response(h) for h in analysis.routing_hops],
        earliest_reliable_sending_node=hop_response(earliest) if earliest else None,
        dkim_signatures=analysis.dkim_signatures,
        findings=analysis.findings,
        note="Header-derived evidence is passive. Earliest reliable sending node is an estimated infrastructure origin, not proof of an attacker's personal IP or identity. DKIM signatures are parsed but not cryptographically verified.",
    )
