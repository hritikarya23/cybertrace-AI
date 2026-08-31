from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import require_roles
from app.database.database import get_db
from app.database.models import Domain, Email, IPAddress, URL, User
from app.schemas.intelligence import DomainIntelligence, IPIntelligence, IntelligenceResponse, URLIntelligence
from app.services.domain_analyzer import analyze_domain
from app.services.ip_analyzer import analyze_ip
from app.services.url_analyzer import analyze_url

router = APIRouter(prefix="/api/v1/emails", tags=["Intelligence"])


def _sender_domain(sender: str | None) -> str | None:
    if not sender or "@" not in sender:
        return None
    return sender.rsplit("@", 1)[-1].strip().lower().strip("><")

@router.post("/{email_id}/intelligence", response_model=IntelligenceResponse)
async def analyze_email_intelligence(
    email_id: int,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Passively analyze stored URLs, domains and IPs. No email URLs are fetched."""
    email = await db.scalar(select(Email).where(Email.id == email_id, Email.user_id == current_user.id))
    if email is None:
        raise HTTPException(status_code=404, detail="Email not found")

    urls = list((await db.scalars(select(URL).where(URL.email_id == email_id))).all())
    domains = list((await db.scalars(select(Domain).where(Domain.email_id == email_id))).all())
    ips = list((await db.scalars(select(IPAddress).where(IPAddress.email_id == email_id))).all())
    sender_domain = _sender_domain(email.sender)

    for item in urls:
        result = analyze_url(item.url)
        item.normalized_url = result.normalized_url
        item.domain = result.domain
        item.scheme = result.scheme
        item.port = result.port
        item.path = result.path
        item.is_shortened = result.is_shortened
        item.is_suspicious = result.is_suspicious
        item.risk_score = result.risk_score
        item.classification = result.classification
        item.reason = result.reason

    domain_results = {}
    for item in domains:
        result = analyze_domain(item.domain, sender_domain)
        domain_results[item.id] = result
        item.is_lookalike = result.is_lookalike
        item.is_suspicious = result.is_suspicious
        item.risk_score = result.risk_score

    for item in ips:
        result = analyze_ip(item.ip)
        item.ip_version = result.ip_version
        item.is_private = result.is_private
        item.risk_score = result.risk_score

    await db.commit()
    return IntelligenceResponse(
        email_id=email_id,
        urls=[URLIntelligence.model_validate(x, from_attributes=True) for x in urls],
        domains=[DomainIntelligence(
            id=x.id, domain=x.domain, is_lookalike=x.is_lookalike,
            target_brand=domain_results[x.id].target_brand, confidence=domain_results[x.id].confidence,
            is_suspicious=x.is_suspicious, risk_score=x.risk_score, reason=domain_results[x.id].reason,
            intelligence_status=domain_results[x.id].intelligence_status
        ) for x in domains],
        ips=[IPIntelligence(
            id=x.id, ip=x.ip, ip_version=x.ip_version, is_private=x.is_private,
            is_public=not x.is_private and analyze_ip(x.ip).is_public,
            is_reserved=analyze_ip(x.ip).is_reserved, is_loopback=analyze_ip(x.ip).is_loopback,
            is_link_local=analyze_ip(x.ip).is_link_local, country=x.country, region=x.region,
            city=x.city, latitude=x.latitude, longitude=x.longitude, isp=x.isp,
            organization=x.organization, asn=x.asn, hosting_provider=x.hosting_provider,
            is_vpn=x.is_vpn, is_proxy=x.is_proxy, is_tor=x.is_tor,
            reputation=x.reputation, risk_score=x.risk_score,
            classification=analyze_ip(x.ip).classification, reason=analyze_ip(x.ip).reason
        ) for x in ips],
    )
